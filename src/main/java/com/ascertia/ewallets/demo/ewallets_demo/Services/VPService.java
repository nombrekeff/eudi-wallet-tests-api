package com.ascertia.ewallets.demo.ewallets_demo.Services;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode; // Import for parsing disclosures
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

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

@Service
public class VPService {
    private static final Logger logger = LoggerFactory.getLogger(VPService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Map<String, Object>> sessionStore = new ConcurrentHashMap<>();
    private final Map<String, String> requestObjectStore = new ConcurrentHashMap<>();

    private ECKey verifierJWK;
    private List<Base64> x5cChain;

    // TODO: Change this to your actual Ngrok/Server URL
    private static final String BASE_URL = "https://test.ewallets.ngrok.app";
    private static final String RESPONSE_URI = BASE_URL + "/api/wallet/callback";

    @PostConstruct
    public void init() {
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        try {
            ClassPathResource resource = new ClassPathResource("verifier.p12");
            if (!resource.exists()) {
                System.err.println("CRITICAL ERROR: 'verifier.p12' NOT FOUND.");
                return;
            }

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            try (InputStream is = resource.getInputStream()) {
                keystore.load(is, "password".toCharArray());
            }

            X509Certificate cert = (X509Certificate) keystore.getCertificate("verifier");
            ECPrivateKey privateKey = (ECPrivateKey) keystore.getKey("verifier", "password".toCharArray());
            ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

            x5cChain = new ArrayList<>();
            x5cChain.add(Base64.encode(cert.getEncoded()));

            verifierJWK = new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID("verifier-key-1")
                    .x509CertChain(x5cChain)
                    .build();

            System.out.println("Identity Loaded. Client ID: " + RESPONSE_URI);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static record AuthRequestResult(String deepLink, String requestJwt, JWTClaimsSet claimsSet) {
    }

    public AuthRequestResult createAuthorizationRequest() throws Exception {
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        Map<String, Object> dcqlQuery = createDcqlQuery();

        ECKey encryptionKey = new ECKey.Builder(verifierJWK.getCurve(), verifierJWK.toECPublicKey())
                .keyID(verifierJWK.getKeyID())
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES)
                .build();

        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(encryptionKey.toPublicJWK().toJSONObject()));

        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put("client_name", "Demo Verifier");
        clientMetadata.put("client_uri", BASE_URL);
        clientMetadata.put("jwks", jwks);

        clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
        clientMetadata.put("authorization_encrypted_response_enc", "A128GCM");
        clientMetadata.put("authorization_encrypted_response_alg_values_supported", List.of("ECDH-ES"));
        clientMetadata.put("authorization_encrypted_response_enc_values_supported", List.of("A128GCM", "A256GCM"));

        Map<String, Object> vpFormats = Map.of(
                "dc+sd-jwt", Map.of(
                        "sd-jwt_alg_values", List.of("ES256", "ES384", "ES512"),
                        "kb-jwt_alg_values", List.of("ES256", "ES384", "ES512")
                ),
                "mso_mdoc", Map.of(
                        "alg", List.of("ES256", "ES384", "ES512", "EdDSA")
                )
        );
        clientMetadata.put("vp_formats_supported", vpFormats);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(RESPONSE_URI)
                .audience("https://self-issued.me/v2")
                .claim("client_id", RESPONSE_URI)
                .claim("client_id_scheme", "redirect_uri")
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post.jwt")
                .claim("response_uri", RESPONSE_URI)
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("dcql_query", dcqlQuery)
                .claim("client_metadata", clientMetadata)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-authz-req+jwt"))
                .x509CertChain(x5cChain)
                .build();

        SignedJWT signedRequestObject = new SignedJWT(header, claimsSet);
        signedRequestObject.sign(new ECDSASigner(verifierJWK));
        String requestJwt = signedRequestObject.serialize();

        String requestObjId = UUID.randomUUID().toString();
        requestObjectStore.put(requestObjId, requestJwt);
        String requestUri = BASE_URL + "/api/wallet/request/" + requestObjId;

        sessionStore.put(state, new HashMap<>(Map.of("status", "PENDING", "nonce", nonce)));

        String deepLink = "eudi-openid4vp://?" +
                "client_id=" + URLEncoder.encode("redirect_uri:" + RESPONSE_URI, StandardCharsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

        return new AuthRequestResult(deepLink, requestJwt, claimsSet);
    }

    private Map<String, Object> createDcqlQuery() {
        Map<String, Object> sdJwtQuery = new HashMap<>();
        sdJwtQuery.put("id", "pid_sd_jwt");
        sdJwtQuery.put("format", "dc+sd-jwt");
        sdJwtQuery.put("meta", Map.of("vct_values", List.of("urn:eudi:pid:1")));
        sdJwtQuery.put("claims", List.of(
                Map.of("path", List.of("family_name")),
                Map.of("path", List.of("given_name")),
                Map.of("path", List.of("birthdate"))
        ));

        return Map.of(
                "credentials", List.of(sdJwtQuery)
        );
    }

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
                return innerJwt.getJWTClaimsSet().toJSONObject();
            } else {
                logger.info("Inner payload is a PlainJWT (Unsigned). Extracting claims...");
                return innerJwt.getJWTClaimsSet().toJSONObject();
            }
        } catch (java.text.ParseException e) {
            logger.warn("Inner payload is NOT a JWT string. Assuming direct JSON payload...");
            return payload.toJSONObject();
        }
    }

    public String getRequestJwt(String id) {
        return requestObjectStore.get(id);
    }

    // --- DATA EXTRACTION LOGIC ---
    public void processWalletResponse(String vpToken, String presentationSubmission, String state) {
        System.out.println(">>> PROCESSING RESPONSE for State: " + state + " <<<");

        Map<String, Object> extractedData = new HashMap<>();

        if (vpToken != null) {
            if (vpToken.contains("~")) {
                // Case 1: SD-JWT (Format: IssuerJWT~Disclosure1~Disclosure2~...~EndJWT)
                System.out.println("Format: SD-JWT detected. " + vpToken);
                extractSdJwtClaims(vpToken, extractedData);
            } else if (vpToken.startsWith("ey")) {
                // Case 2: Standard JWT
                System.out.println("Format: Standard JWT detected.");
                // Add JWT parsing if needed
            } else {
                // Case 3: mDoc (CBOR Base64) - Requires 'jackson-dataformat-cbor'
                System.out.println("Format: mDoc (Binary/CBOR) detected.");
                System.out.println("NOTE: To parse mDoc, you need 'jackson-dataformat-cbor' dependency.");
                extractedData.put("raw_mdoc", vpToken);
            }
        }

        if (sessionStore.containsKey(state)) {
            Map<String, Object> session = sessionStore.get(state);
            session.put("status", "RECEIVED");
            session.put("raw_token", vpToken);
            session.put("extracted_data", extractedData); // <--- Store extracted names
            session.put("submission", presentationSubmission);
            logger.info("Session updated. Extracted Data: " + extractedData);
        } else {
            logger.warn("Received response for unknown state: " + state);
        }
    }

    private void extractSdJwtClaims(String sdJwt, Map<String, Object> output) {
        try {
            String[] parts = sdJwt.split("~");
            System.out.println("SD-JWT Parts: " + parts.length);

            // Iterate over disclosures (Indices 1 to N-1)
            for (int i = 1; i < parts.length; i++) {
                String disclosure = parts[i];
                if (disclosure.isEmpty()) continue;

                try {
                    // Disclosures are Base64URL encoded JSON arrays: ["salt", "key", "value"]
                    byte[] decodedBytes = com.nimbusds.jose.util.Base64URL.from(disclosure).decode();
                    String jsonStr = new String(decodedBytes);

                    // Parse JSON Array
                    if (jsonStr.startsWith("[")) {
                        JsonNode node = objectMapper.readTree(jsonStr);
                        if (node.isArray() && node.size() >= 3) {
                            String key = node.get(1).asText();
                            JsonNode valueNode = node.get(2);

                            // Check for the specific keys you want
                            if ("family_name".equals(key) || "given_name".equals(key)) {
                                System.out.println("FOUND CLAIM: " + key + " = " + valueNode.asText());
                                output.put(key, valueNode.asText());
                            }
                        }
                    }
                } catch (Exception e) {
                    // Ignore parts that aren't disclosures (like the Key Binding JWT at the end)
                }
            }
        } catch (Exception e) {
            System.err.println("Error parsing SD-JWT: " + e.getMessage());
        }
    }

    public Map<String, Object> getSessionStatus(String state) {
        return sessionStore.getOrDefault(state, Map.of("status", "NOT_FOUND"));
    }
}