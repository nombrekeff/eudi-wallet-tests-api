package com.ascertia.ewallets.demo.ewallets_demo.services;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// TODO: try using liobraries like 'com.authzee:sd-jwt-lib' for SD-JWT parsing, and generating the requests.
//  if not, implement light request generation and SD-JWT parsing directly here, but make classes and structures for type safety.

// TODO: Separate the VPService into smaller services: KeyManagementService, RequestService, ResponseService, etc.
// TODO: Create models for the request and response structures for type safety.
// TODO: Add proper error handling and logging throughout the service.
// TODO: Make everything configurable via application.properties or environment variables.
// TODO: Add unit and integration tests for all functionalities.
// TODO: Add request builder of sorts for the DCQL queries and claims.
// TODO: Abstract all cryptographic operations into a separate utility class or service.
// TODO: Abstract the request generation and response handling

@Service
public class VPService {
    private static final Logger logger = LoggerFactory.getLogger(VPService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    // In-memory stores for sessions and request objects: in production, use a persistent store / vault
    private final Map<String, Map<String, Object>> sessionStore = new ConcurrentHashMap<>();
    private final Map<String, String> requestObjectStore = new ConcurrentHashMap<>();
    private final CBORMapper cborMapper = new CBORMapper(); // For parsing mDoc


    private ECKey verifierJWK;
    private List<Base64> x5cChain;

    private static final String BASE_URL = "https://test.ewallets.ngrok.app";
    private static final String RESPONSE_URI = BASE_URL + "/api/wallet/callback";
    private static final String verifierP12Location = "verifier.p12";
    private static final String verifierP12Password = "password";
    private static final String verifierKeyID = "verifier-key-1";

    @PostConstruct
    public void init() {
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        loadIdentity();
    }

    /**
     * Loads the verifier's identity from a PKCS12 keystore.
     */
    public void loadIdentity() {
        try {
            ClassPathResource resource = new ClassPathResource(verifierP12Location);

            if (!resource.exists()) {
                logger.error("CRITICAL ERROR: 'verifier.p12' NOT FOUND.");
                return;
            }

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            try (InputStream is = resource.getInputStream()) {
                keystore.load(is, verifierP12Password.toCharArray());
            }

            X509Certificate cert = (X509Certificate) keystore.getCertificate("verifier");
            ECPrivateKey privateKey = (ECPrivateKey) keystore.getKey("verifier", verifierP12Password.toCharArray());
            ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

            x5cChain = new ArrayList<>();
            x5cChain.add(Base64.encode(cert.getEncoded()));

            verifierJWK = new ECKey
                    .Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(verifierKeyID)
                    .x509CertChain(x5cChain)
                    .build();

            logger.info("Identity Loaded. Client ID: " + RESPONSE_URI);

        } catch (Exception e) {
            logger.error("{}:{}", e.getMessage(), Arrays.toString(e.getStackTrace()));
        }
    }

    /**
     * Creates an authorization request for the VP token flow.
     *
     * @return An AuthRequestResult containing the deep link, request JWT, and claims set.
     * @throws Exception If there is an error during request creation.
     */
    public AuthRequestResult createAuthorizationRequest() throws Exception {
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        Map<String, Object> dcqlQuery = createDcqlQuery();

        ECKey encryptionKey = new ECKey.Builder(verifierJWK.getCurve(), verifierJWK.toECPublicKey()).keyID(verifierJWK.getKeyID()).keyUse(KeyUse.ENCRYPTION).algorithm(JWEAlgorithm.ECDH_ES).build();

        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(encryptionKey.toPublicJWK().toJSONObject()));

        Map<String, Object> clientMetadata = getClientMetadata(jwks);
        Map<String, Object> vpFormats = getVpFormats();

        clientMetadata.put("vp_formats_supported", vpFormats);

        JWTClaimsSet claimsSet = getJwtClaimsSet(nonce, state, dcqlQuery, clientMetadata);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("oauth-authz-req+jwt")).x509CertChain(x5cChain).build();

        SignedJWT signedRequestObject = new SignedJWT(header, claimsSet);
        signedRequestObject.sign(new ECDSASigner(verifierJWK));
        String requestJwt = signedRequestObject.serialize();

        String requestObjId = UUID.randomUUID().toString();
        requestObjectStore.put(requestObjId, requestJwt);

        String requestUri = BASE_URL + "/api/wallet/request/" + requestObjId;

        sessionStore.put(state, new HashMap<>(Map.of("status", "PENDING", "nonce", nonce)));

        String deepLink = generateDeeplink(requestUri, RESPONSE_URI + "/" + state);

        return new AuthRequestResult(deepLink, requestJwt, claimsSet);
    }

    private static String generateDeeplink(String requestUri, String redirectUri) throws Exception {
        return "eudi-openid4vp://?" + "client_id=" + URLEncoder.encode("redirect_uri:" + redirectUri, StandardCharsets.UTF_8) + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
    }

    private static JWTClaimsSet getJwtClaimsSet(
            String nonce,
            String state,
            Map<String, Object> dcqlQuery,
            Map<String, Object> clientMetadata
    ) {
        return new JWTClaimsSet.Builder()
                .issuer(RESPONSE_URI)
                .audience("https://self-issued.me/v2")
                .claim("client_id", RESPONSE_URI)
                .claim("client_id_scheme", "redirect_uri")
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post.jwt")
                .claim("response_uri", RESPONSE_URI + "/" + state)
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("dcql_query", dcqlQuery)
                .claim("client_metadata", clientMetadata)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();
    }

    private static Map<String, Object> getVpFormats() {
        return Map.of(
                "dc+sd-jwt", Map.of(
                        "sd-jwt_alg_values", List.of("ES256", "ES384", "ES512"),
                        "kb-jwt_alg_values", List.of("ES256", "ES384", "ES512")
                ),
                "mso_mdoc", Map.of("alg", List.of("ES256", "ES384", "ES512", "EdDSA"))
        );
    }

    private static Map<String, Object> getClientMetadata(Map<String, Object> jwks) {
        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put("client_name", "Demo Verifier");
        clientMetadata.put("client_uri", BASE_URL);
        clientMetadata.put("jwks", jwks);

        clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
        clientMetadata.put("authorization_encrypted_response_enc", "A128GCM");
        clientMetadata.put("authorization_encrypted_response_alg_values_supported", List.of("ECDH-ES"));
        clientMetadata.put("authorization_encrypted_response_enc_values_supported", List.of("A128GCM", "A256GCM"));

        return clientMetadata;
    }

    /**
     * Creates a DCQL query requesting specific claims.
     *
     * @return A map representing the DCQL query.
     */
    private Map<String, Object> createDcqlQuery() {
//        "org.iso.23220.2.photoid.1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1", "eu.europa.ec.eudi.pid.1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:1"
//        var queryBuilder = new DcqlBuild();
//        queryBuilder.credential("pid_sd_jwt")
//                .format(DcqlFormat.DC_SD_JWT)
////              .meta("vct_values", List.of("urn:eudi:pid:1")) // Meta can be added automatically based on credential ID
//                .claimPath("family_name")
//                .claimPath("given_name")
//                .claimPath("birthdate");
//
//        queryBuilder.credential("id_photo_card")
//                .format(DcqlFormat.MSO_MDOC)
////               .meta("doctype_value", "org.iso.23220.photoid.1") // Meta can be added automatically based on credential ID
//                .claimPath("family_name") // Will add if and path org namespace automatically
//                .claimPath("given_name")
//                .claimPath("birthdate");

        Map<String, Object> sdJwtQuery = new HashMap<>();
        sdJwtQuery.put("id", "pid_sd_jwt");
        sdJwtQuery.put("format", "dc+sd-jwt");
        sdJwtQuery.put("meta", Map.of(
                "vct_values", List.of("urn:eudi:pid:1"))
        );
        sdJwtQuery.put("claims", List.of(
                        Map.of("path", List.of("family_name")),
                        Map.of("path", List.of("given_name")),
                        Map.of("path", List.of("birthdate"))
                )
        );

        Map<String, Object> msoMdocQuery = new HashMap<>();
        msoMdocQuery.put("id", "mdl-id");
        msoMdocQuery.put("format", "mso_mdoc");
        msoMdocQuery.put("meta", Map.of(
                "doctype_value", "org.iso.18013.5.1.mDL")
        );
        msoMdocQuery.put("claims", List.of(
                        Map.of("id", "family_name", "path", List.of("org.iso.18013.5.1", "family_name")),
                        Map.of("id", "given_name", "path", List.of("org.iso.18013.5.1", "given_name")),
                        Map.of("id", "portrait", "path", List.of("org.iso.18013.5.1", "portrait"))
                )
        );


        return Map.of(
                "credentials", List.of(
                        msoMdocQuery
//                        sdJwtQuery
//                        , msoMdocQuery
                ),
                "credential_set", List.of(
                        Map.of("options", List.of("photo_card", "pid_sd_jwt"))
                )
        );
    }

    /**
     * Retrieves the stored request JWT by its ID.
     *
     * @param id The unique identifier for the request JWT.
     * @return The corresponding JWT string, or null if not found.
     */
    public String getRequestJwt(String id) {
        return requestObjectStore.get(id);
    }


    /**
     * Decrypts an encrypted JARM JWE response and extracts the claims.
     *
     * @param encryptedResponse The encrypted JARM JWE string.
     * @return A map of claims extracted from the decrypted payload.
     * @throws Exception If decryption or parsing fails.
     */
    public Map<String, Object> decryptJarmResponse(String encryptedResponse) throws Exception {
        logger.info("Decrypting JARM JWE...");

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(encryptedResponse);
        ECDHDecrypter decrypter = new ECDHDecrypter(verifierJWK.toECPrivateKey());

        encryptedJWT.decrypt(decrypter);
        Payload payload = encryptedJWT.getPayload();

        try {
            JWT innerJwt = JWTParser.parse(payload.toString());

            if (innerJwt instanceof SignedJWT) {
                logger.info("Inner payload IS a SignedJWT. Extracting claims...");
            } else {
                logger.info("Inner payload is a PlainJWT (Unsigned). Extracting claims...");
            }

            return innerJwt.getJWTClaimsSet().toJSONObject();
        } catch (java.text.ParseException e) {
            logger.warn("Inner payload is NOT a JWT string. Assuming direct JSON payload...");
            return payload.toJSONObject();
        }
    }


    public ResponseEntity<String> handleWalletResponse(String pathId, Map<String, String> params, HttpServletRequest request) {
        logger.info(">>> WALLET CALLBACK HIT (POST) <<<");
        logger.info("pathId: {}", pathId);

        String vpToken = null;
        String presentationSubmission = null;
        String state = null;
        String jarmResponse = null;

        try {
            if (params != null && !params.isEmpty()) {
                vpToken = params.get("vp_token");
                presentationSubmission = params.get("presentation_submission");
                state = params.get("state");
                jarmResponse = params.get("response");
            }

            if (vpToken == null && jarmResponse == null && request.getContentType() != null && request.getContentType().contains("json")) {
                try {
                    StringBuilder buffer = new StringBuilder();
                    BufferedReader reader = request.getReader();

                    String line;
                    while ((line = reader.readLine()) != null) buffer.append(line);

                    String jsonStr = buffer.toString();
                    if (!jsonStr.isEmpty()) {
                        Map<String, Object> json = objectMapper
                                .readValue(jsonStr, new TypeReference<>() {
                                });

                        if (json.containsKey("response")) jarmResponse = json.get("response").toString();
                        if (json.containsKey("state")) state = json.get("state").toString();
                        if (json.containsKey("vp_token")) {
                            vpToken = extractTokenString(json.get("vp_token"));
                        }
                    }
                } catch (Exception e) {
                    logger.info("JSON Body parse failed: {}", e.getMessage());
                }
            }

            if (state == null && pathId != null && !pathId.isEmpty()) {
                state = pathId;
            }

            if (jarmResponse != null) {
                logger.info("Status: Encrypted JARM received.");
                try {
                    Map<String, Object> claims = decryptJarmResponse(jarmResponse);
                    if (claims.containsKey("state")) state = (String) claims.get("state");

                    Object tokenObj = claims.get("vp_token");
                    vpToken = extractTokenString(tokenObj);

                    Object submissionObj = claims.get("presentation_submission");
                    if (submissionObj != null) {
                        presentationSubmission = objectMapper.writeValueAsString(submissionObj);
                    }
                } catch (Exception e) {
                    System.err.println("JARM Decryption Failed: " + e.getMessage());
                    return ResponseEntity.badRequest().body("Decryption failed: " + e.getMessage());
                }
            }

            if (vpToken != null && state != null) {
                logger.info("Status: Valid Token Extracted.");
                processWalletResponse(vpToken, presentationSubmission, state);
                return ResponseEntity.ok("Verified");
            }

            return ResponseEntity.badRequest().body("Invalid Request: No token found");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Server Error processing callback");
        }
    }

    // --- Helper to extract actual token string from nested structure ---
    private String extractTokenString(Object tokenObj) {
        switch (tokenObj) {
            case null -> {
                return null;
            }
            case String s -> {
                return s;
            }
            case List<?> list -> {
                if (!list.isEmpty()) return extractTokenString(list.getFirst()); // Recurse
            }
            default -> {
            }
        }

        if (tokenObj instanceof Map<?, ?> map && !map.isEmpty()) {
            // Usually { "id": ["token"] } or { "id": "token" }
            // We take the first value found
            return extractTokenString(map.values().iterator().next()); // Recurse
        }

        return tokenObj.toString();
    }

    public void processWalletResponse(String vpToken, String presentationSubmission, String state) {
        logger.info(">>> PROCESSING RESPONSE for State: {} <<<", state);

        // Sanitize token string
        String cleanToken = vpToken.trim().replace(" ", "");

        // Remove potential surrounding quotes from bad stringification
        if (cleanToken.startsWith("\"") && cleanToken.endsWith("\"")) {
            cleanToken = cleanToken.substring(1, cleanToken.length() - 1);
        }

        Map<String, Object> extractedData = new HashMap<>();

        if (cleanToken.contains("~")) {
            logger.info("Format: SD-JWT detected.");
            extractSdJwtClaims(cleanToken, extractedData);
        } else {
            logger.info("Format: mDoc (Binary/CBOR) detected.");
            extractMdocData(cleanToken, extractedData);
        }

        if (sessionStore.containsKey(state)) {
            Map<String, Object> session = sessionStore.get(state);
            session.put("status", "RECEIVED");
            session.put("raw_token", cleanToken);
            session.put("extracted_data", extractedData);
            session.put("submission", presentationSubmission);
            logger.info("Session updated. Extracted Data: {}", extractedData);
        } else {
            logger.warn("Received response for unknown state: {}", state);
        }
    }

    private void extractSdJwtClaims(String sdJwt, Map<String, Object> output) {
        try {
            String[] parts = sdJwt.split("~");

            for (int i = 1; i < parts.length; i++) {
                String disclosure = parts[i];

                if (disclosure.isEmpty()) continue;

                try {
                    byte[] decodedBytes = com.nimbusds.jose.util.Base64URL.from(disclosure).decode();
                    String jsonStr = new String(decodedBytes);

                    if (!jsonStr.startsWith("[")) continue;

                    JsonNode node = objectMapper.readTree(jsonStr);
                    if (node == null || !node.isArray() || node.size() < 3) continue;

                    String key = node.get(1).asText();
                    JsonNode valueNode = node.get(2);
                    output.put(key, valueNode.asText());
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e) {
            logger.error("Error parsing SD-JWT: {}", e.getMessage());
        }
    }

    private void extractMdocData(String vpToken, Map<String, Object> output) {
        try {
            // Decode Base64 URL Safe string to bytes
            byte[] mdocBytes = java.util.Base64.getUrlDecoder().decode(vpToken);

            // Parse outer CBOR structure
            JsonNode root = cborMapper.readTree(mdocBytes);

            // Structure: documents -> [0] -> issuerSigned -> nameSpaces
            JsonNode documents = root.get("documents");
            boolean hasDocuments = documents != null && documents.isArray() && !documents.isEmpty();

            if (!hasDocuments) {
                logger.warn("No documents found in mDoc VP.");
                return;
            }


            JsonNode firstDoc = documents.get(0);
            JsonNode issuerSigned = firstDoc.get("issuerSigned");
            if (issuerSigned == null) return;

            JsonNode nameSpaces = issuerSigned.get("nameSpaces");
            if (nameSpaces == null) return;

            // Check known namespaces
            List<String> namespacesToCheck = List.of("eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1");

            for (String ns : namespacesToCheck) {
                JsonNode nsData = nameSpaces.get(ns);
                if (nsData == null) continue;
                if (!nsData.isArray()) continue;

                for (JsonNode item : nsData) {
                    if (!item.isBinary()) continue;
                    try {
                        byte[] itemBytes = item.binaryValue();
                        JsonNode itemNode = cborMapper.readTree(itemBytes);

                        if (itemNode.has("elementIdentifier") && itemNode.has("elementValue")) {
                            String key = itemNode.get("elementIdentifier").asText();
                            String value = itemNode.get("elementValue").asText();
                            logger.info("FOUND mDoc CLAIM: {} = {}", key, value);
                            output.put(key, value);
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error parsing mDoc CBOR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Retrieves the session status for a given state.
     *
     * @param state The state parameter to look up.
     * @return A map containing the session status and any associated data.
     */
    public Map<String, Object> getSessionStatus(String state) {
        return sessionStore.getOrDefault(state, Map.of("status", "NOT_FOUND"));
    }

    public record AuthRequestResult(String deepLink, String requestJwt, JWTClaimsSet claimsSet) {
    }
}