package com.ascertia.ewallets.demo.ewallets_demo.Services;

import com.fasterxml.jackson.annotation.JsonInclude;
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

        // 1. DCQL Query
        Map<String, Object> dcqlQuery = createDcqlQuery();

        // 2. Prepare Encryption Key (CRITICAL: "use": "enc")
        ECKey encryptionKey = new ECKey.Builder(verifierJWK.getCurve(), verifierJWK.toECPublicKey())
                .keyID(verifierJWK.getKeyID())
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES)
                .build();

        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(encryptionKey.toPublicJWK().toJSONObject()));

        // 3. Client Metadata
        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put("client_name", "Demo Verifier");
        clientMetadata.put("client_uri", BASE_URL);
        clientMetadata.put("jwks", jwks);

        // JARM Encryption Params
        clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
        clientMetadata.put("authorization_encrypted_response_enc", "A128GCM");
        clientMetadata.put("authorization_encrypted_response_alg_values_supported", List.of("ECDH-ES"));
        clientMetadata.put("authorization_encrypted_response_enc_values_supported", List.of("A128GCM", "A256GCM"));

        // VP Formats (Required by EUDI Wallet Kit)
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

        // 4. JWT Construction
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(RESPONSE_URI)
                .audience("https://self-issued.me/v2")
                .claim("client_id", RESPONSE_URI)
                .claim("client_id_scheme", "redirect_uri")
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post.jwt") // Requesting Encrypted Response
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

        // 5. Deep Link
        String deepLink = "eudi-openid4vp://?" +
                "client_id=" + URLEncoder.encode("redirect_uri:" + RESPONSE_URI, StandardCharsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

        return new AuthRequestResult(deepLink, requestJwt, claimsSet);
    }

    private Map<String, Object> createDcqlQuery() {
        // SD-JWT PID Query
        Map<String, Object> sdJwtQuery = new HashMap<>();
        sdJwtQuery.put("id", "pid_sd_jwt");
        sdJwtQuery.put("format", "dc+sd-jwt");
        sdJwtQuery.put("meta", Map.of("vct_values", List.of("urn:eudi:pid:1")));
        sdJwtQuery.put("claims", List.of(
                Map.of("path", List.of("family_name")),
                Map.of("path", List.of("given_name")),
                Map.of("path", List.of("birthdate"))
        ));

        // mDoc PID Query
        Map<String, Object> mdocQuery = new HashMap<>();
        mdocQuery.put("id", "pid_mdoc");
        mdocQuery.put("format", "mso_mdoc");
        mdocQuery.put("meta", Map.of("doctype_values", List.of("eu.europa.ec.eudi.pid.1")));
        mdocQuery.put("claims", List.of(
                Map.of("path", List.of("eu.europa.ec.eudi.pid.1", "family_name")),
                Map.of("path", List.of("eu.europa.ec.eudi.pid.1", "given_name"))
        ));

        return Map.of(
                "credentials", List.of(
                        sdJwtQuery
                        // , mdocQuery // Uncomment to test mDoc instead or in addition
                )
        );
    }

    /**
     * Decrypts a JARM (JWE) response from the wallet.
     */
    public Map<String, Object> decryptJarmResponse(String encryptedResponse) throws Exception {
        logger.info("Decrypting JARM JWE...");

        // 1. Parse JWE
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(encryptedResponse);

        // 2. Decrypt using our Private Key
        ECDHDecrypter decrypter = new ECDHDecrypter(verifierJWK.toECPrivateKey());
        encryptedJWT.decrypt(decrypter);

        // 3. Extract the Inner Payload. It might be a Signed JWT (JWS) or just a JWT.
        // The payload is a STRING which is another JWT.
        Payload payload = encryptedJWT.getPayload();

        // Try to parse the payload as a JWT object (generic)
        JWT innerJwt;
        try {
            innerJwt = JWTParser.parse(payload.toString());
        } catch (java.text.ParseException e) {
            // Fallback: Maybe the wallet sent just the JSON claims directly inside the JWE?
            // (Not standard JARM, but possible in some implementations)
            logger.warn("Inner payload is not a JWT string. Trying JSON...");
            return payload.toJSONObject();
        }

        if (innerJwt instanceof SignedJWT) {
            logger.info("Inner payload IS a SignedJWT. Extracting claims...");
            return innerJwt.getJWTClaimsSet().toJSONObject();
        } else {
            logger.info("Inner payload is a PlainJWT (Unsigned). Extracting claims...");
            return innerJwt.getJWTClaimsSet().toJSONObject();
        }
    }

    public String getRequestJwt(String id) {
        return requestObjectStore.get(id);
    }

    public void processWalletResponse(String vpToken, String presentationSubmission, String state) {
        System.out.println(">>> PROCESSING RESPONSE <<<");
        System.out.println("State: " + state);

        // Here you would normally:
        // 1. Validate the nonce matches sessionStore.get(state).nonce
        // 2. Verify the vpToken signature (SD-JWT or mDoc CBOR)

        if (sessionStore.containsKey(state)) {
            Map<String, Object> session = sessionStore.get(state);
            session.put("status", "RECEIVED");
            session.put("raw_token", vpToken);
            session.put("submission", presentationSubmission);
            logger.info("Session updated for state: " + state);
        } else {
            logger.warn("Received response for unknown state: " + state);
        }
    }

    public Map<String, Object> getSessionStatus(String state) {
        return sessionStore.getOrDefault(state, Map.of("status", "NOT_FOUND"));
    }
}