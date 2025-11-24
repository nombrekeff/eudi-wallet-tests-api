package com.ascertia.ewallets.demo.ewallets_demo.Services;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class VPService {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Map<String, Object>> sessionStore = new ConcurrentHashMap<>();
    private final Map<String, String> requestObjectStore = new ConcurrentHashMap<>();

    private ECKey verifierJWK;
    private List<Base64> x5cChain;

    private static final String BASE_URL = "https://81f01ccd468a.ngrok.app";
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

    public String createAuthorizationRequest() throws Exception {
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        Map<String, Object> presentationDefinition = createPidPresentationDefinition();

        String client_id = RESPONSE_URI;

        // REMOVED: client_metadata for now to avoid triggering strict JARM checks

        // JWT Construction
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(client_id)
                .subject(client_id)
                .audience("https://self-issued.me/v2")
                .claim("client_id", client_id)
                .claim("client_id_scheme", "redirect_uri")
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post")
                .claim("response_uri", RESPONSE_URI)
                .claim("redirect_uri", RESPONSE_URI)
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("presentation_definition", presentationDefinition)
                //.claim("client_metadata", clientMetadata) // Commented out
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

        // DEEP LINK
        String deepLink = "eudi-openid4vp://?" +
                "client_id=" + URLEncoder.encode("redirect_uri:" + client_id, StandardCharsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8) +
                "&response_type=vp_token" +
                "&client_id_scheme=redirect_uri";

        sessionStore.put(state, new HashMap<>(Map.of("status", "PENDING", "nonce", nonce)));

        return deepLink;
    }

    private Map<String, Object> createPidPresentationDefinition() {
        Map<String, Object> constraints = Map.of(
                "fields", List.of(
                        Map.of("path", List.of("$.credentialSubject.family_name", "$.credentialSubject.name_family"), "intent_to_retain", false),
                        Map.of("path", List.of("$.credentialSubject.given_name", "$.credentialSubject.name_given"), "intent_to_retain", false)
                )
        );

        Map<String, Object> inputDescriptor = new HashMap<>();
        inputDescriptor.put("id", "eu.europa.ec.eudi.pid.1");
        inputDescriptor.put("name", "EUDI PID");
        inputDescriptor.put("purpose", "Verify Identity");
        inputDescriptor.put("constraints", constraints);

        // KEEP FORMATS BROAD
        inputDescriptor.put("format", Map.of(
                "dc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512")),
                "vc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512")),
                "mso_mdoc",  Map.of("alg", List.of("ES256", "ES384", "ES512", "EdDSA"))
        ));

        return Map.of(
                "id", UUID.randomUUID().toString(),
                "input_descriptors", List.of(inputDescriptor)
        );
    }

    public String getRequestJwt(String id) {
        return requestObjectStore.get(id);
    }

    public void processWalletResponse(String vpToken, String presentationSubmission, String state) {
        System.out.println(">>> WALLET CALLBACK RECEIVED <<<");
        System.out.println("State: " + state);
        System.out.println("VP Token Size: " + (vpToken != null ? vpToken.length() : "null"));

        if (sessionStore.containsKey(state)) {
            sessionStore.get(state).put("status", "RECEIVED");
            sessionStore.get(state).put("raw_token", vpToken);
        }
    }

    public Map<String, Object> getSessionStatus(String state) {
        return sessionStore.getOrDefault(state, Map.of("status", "NOT_FOUND"));
    }
}