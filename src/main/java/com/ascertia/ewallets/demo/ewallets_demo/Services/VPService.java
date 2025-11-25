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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger logger = LoggerFactory.getLogger(VPService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Map<String, Object>> sessionStore = new ConcurrentHashMap<>();
    private final Map<String, String> requestObjectStore = new ConcurrentHashMap<>();

    private ECKey verifierJWK;
    private List<Base64> x5cChain;

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

            // Check SAN match (Critical for 'redirect_uri' scheme)
            boolean sanMatch = false;
            if (cert.getSubjectAlternativeNames() != null) {
                for (List<?> san : cert.getSubjectAlternativeNames()) {
                    // Type 6 = URI
                    if (san.get(0).equals(6) && san.get(1).toString().startsWith(BASE_URL)) {
                        sanMatch = true;
                    }
                }
            }

            if (!sanMatch) {
                System.err.println("--- WARNING: Certificate SAN does not match BASE_URL ---");
            }

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

        // 1. Create the DCQL Query (The modern replacement for Presentation Definition)
        Map<String, Object> dcqlQuery = createDcqlQuery();

        // 2. Client Metadata (Must include JWKS for encryption if using direct_post.jwt)
        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(verifierJWK.toPublicJWK().toJSONObject()));

        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put("client_name", "Demo Verifier");
        clientMetadata.put("client_uri", BASE_URL);
        clientMetadata.put("jwks", jwks);
        // Encryption algorithms supported by your verifier
        clientMetadata.put("authorization_encrypted_response_alg", "ECDH-ES");
        clientMetadata.put("authorization_encrypted_response_enc", "A256GCM");

        // 3. JWT Construction
        // Note: 'client_id_scheme' can remain 'redirect_uri' if your cert SAN matches the URL.
        // The official verifier uses 'x509_san_sha256' which is more complex, but 'redirect_uri' is standard.
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(RESPONSE_URI)
                .audience("https://self-issued.me/v2")
                .claim("client_id", RESPONSE_URI)
                .claim("client_id_scheme", "redirect_uri") // Keep this if your cert setup relies on it
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post.jwt") // EUDI Wallets prefer Encrypted JWT responses
                .claim("response_uri", RESPONSE_URI)
                .claim("nonce", nonce)
                .claim("state", state)
                .claim("dcql_query", dcqlQuery) // <--- INJECT DCQL HERE
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

        // 4. Deep Link
        String deeplink= "eudi-openid4vp://?" +
                "client_id=" + URLEncoder.encode("redirect_uri:" + RESPONSE_URI, StandardCharsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

        return new AuthRequestResult(deeplink, requestJwt, claimsSet);
    }

    // --- NEW DCQL GENERATION METHOD ---
    private Map<String, Object> createDcqlQuery() {
        // Query 1: SD-JWT PID (Matches the official verifier example)
        Map<String, Object> sdJwtQuery = new HashMap<>();
        sdJwtQuery.put("id", "pid_sd_jwt");
        sdJwtQuery.put("format", "dc+sd-jwt");
        sdJwtQuery.put("meta", Map.of("vct_values", List.of("urn:eudi:pid:1")));
        sdJwtQuery.put("claims", List.of(
                Map.of("path", List.of("family_name")),
                Map.of("path", List.of("given_name")),
                Map.of("path", List.of("birthdate"))
        ));

        // Query 2: mDoc PID (ISO 18013-5)
        // Note: mDoc uses 'doctype_values' and [namespace, element] paths
        Map<String, Object> mdocQuery = new HashMap<>();
        mdocQuery.put("id", "pid_mdoc");
        mdocQuery.put("format", "mso_mdoc");
        mdocQuery.put("meta", Map.of("doctype_values", List.of("eu.europa.ec.eudi.pid.1")));
        mdocQuery.put("claims", List.of(
                Map.of("path", List.of("eu.europa.ec.eudi.pid.1", "family_name")),
                Map.of("path", List.of("eu.europa.ec.eudi.pid.1", "given_name")),
                Map.of("path", List.of("eu.europa.ec.eudi.pid.1", "birth_date"))
        ));

        // Combine them.
        // NOTE: Sending BOTH in the array might interpret as "I want BOTH credentials".
        // To support "Either/Or", advanced DCQL logic is needed, but for a PoC,
        // it is safer to ask for the one you want to test.
        // UNCOMMENT 'mdocQuery' below to test mdoc, or send both if you want to see if the wallet handles multi-credential requests.
        return Map.of(
                "credentials", List.of(
                        sdJwtQuery
                        // , mdocQuery // <--- Uncomment this line to also ask for mDoc
                )
        );
    }

    private Map<String, Object> createPidPresentationDefinition() {
        // --- 1. Define Input Descriptor for mdoc (ISO 18013-5) ---
        Map<String, Object> mdocConstraints = Map.of(
                "limit_disclosure", "required",
                "fields", List.of(
                        // Filter: Must be a PID mdoc
                        Map.of(
                                "path", List.of("$.docType"), // Standard path for docType check
                                "filter", Map.of("type", "string", "const", "eu.europa.ec.eudi.pid.1")
                        ),
                        // Data: Family Name
                        Map.of(
                                "path", List.of("$['eu.europa.ec.eudi.pid.1']['family_name']"),
                                "intent_to_retain", false
                        ),
                        // Data: Given Name
                        Map.of(
                                "path", List.of("$['eu.europa.ec.eudi.pid.1']['given_name']"),
                                "intent_to_retain", false
                        )
                )
        );

        Map<String, Object> mdocDescriptor = new HashMap<>();
        mdocDescriptor.put("id", "pid-mdoc");
        mdocDescriptor.put("group", List.of("alternative_A")); // Grouping for "Pick 1" logic
        mdocDescriptor.put("format", Map.of(
                "mso_mdoc", Map.of("alg", List.of("ES256", "ES384", "ES512", "EdDSA"))
        ));
        mdocDescriptor.put("constraints", mdocConstraints);

        // --- 2. Define Input Descriptor for SD-JWT ---
        Map<String, Object> sdJwtConstraints = Map.of(
                "limit_disclosure", "required",
                "fields", List.of(
                        // Filter: Must be a PID SD-JWT (Check your issuer's exact VCT string)
                        Map.of(
                                "path", List.of("$.vct"),
                                "filter", Map.of("type", "string", "const", "urn:eu.europa.ec.eudi.pid.1")
                        ),
                        // Data: Family Name
                        Map.of(
                                "path", List.of("$.credentialSubject.family_name", "$.credentialSubject.name_family"),
                                "intent_to_retain", false
                        ),
                        // Data: Given Name
                        Map.of(
                                "path", List.of("$.credentialSubject.given_name", "$.credentialSubject.name_given"),
                                "intent_to_retain", false
                        )
                )
        );

        Map<String, Object> sdJwtDescriptor = new HashMap<>();
        sdJwtDescriptor.put("id", "pid-sdjwt");
        sdJwtDescriptor.put("group", List.of("alternative_A"));
        sdJwtDescriptor.put("format", Map.of(
                "dc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512")),
                "vc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512"))
        ));
        sdJwtDescriptor.put("constraints", sdJwtConstraints);

        // --- 3. Submission Requirements (Logic: OR) ---
        Map<String, Object> submissionRequirement = Map.of(
                "rule", "pick",
                "count", 1,
                "from", "alternative_A",
                "name", "EUDI PID Selection"
        );

        return Map.of(
                "id", UUID.randomUUID().toString(),
                "input_descriptors", List.of(mdocDescriptor, sdJwtDescriptor),
                "submission_requirements", List.of(submissionRequirement)
        );
    }
//    private Map<String, Object> createPidPresentationDefinition() {
//        Map<String, Object> constraints = Map.of(
//                "fields", List.of(
//                        Map.of(
//                                "path", List.of(
//                                        // SD-JWT / JWT paths
//                                        "$.credentialSubject.family_name",
//                                        "$.credentialSubject.name_family",
//                                        // mDoc paths (Namespace: eu.europa.ec.eudi.pid.1)
//                                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
//                                ),
//                                "intent_to_retain", false
//                        ),
//                        Map.of(
//                                "path", List.of(
//                                        // SD-JWT / JWT paths
//                                        "$.credentialSubject.given_name",
//                                        "$.credentialSubject.name_given",
//                                        // mDoc paths
//                                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
//                                ),
//                                "intent_to_retain", false
//                        )
//                )
//        );
//
//        Map<String, Object> inputDescriptor = new HashMap<>();
//        inputDescriptor.put("id", "eu.europa.ec.eudi.pid.1");
//        inputDescriptor.put("name", "EUDI PID");
//        inputDescriptor.put("purpose", "Verify Identity");
//        inputDescriptor.put("constraints", constraints);
//
//        // FORMATS
//        inputDescriptor.put("format", Map.of(
//                "dc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512")),
//                "vc+sd-jwt", Map.of("alg", List.of("ES256", "ES384", "ES512")),
//                "mso_mdoc",  Map.of("alg", List.of("ES256", "ES384", "ES512", "EdDSA"))
//        ));
//
//        return Map.of(
//                "id", UUID.randomUUID().toString(),
//                "input_descriptors", List.of(inputDescriptor)
//        );
//    }

    public String getRequestJwt(String id) {
        return requestObjectStore.get(id);
    }

    public void processWalletResponse(String vpToken, String presentationSubmission, String state) {
        System.out.println(">>> WALLET CALLBACK RECEIVED <<<");
        System.out.println("State: " + state);
        System.out.println("Token Content: " + (vpToken != null ? "PRESENT" : "NULL"));

        if (sessionStore.containsKey(state)) {
            sessionStore.get(state).put("status", "RECEIVED");
            sessionStore.get(state).put("raw_token", vpToken);
        }
    }

    public Map<String, Object> getSessionStatus(String state) {
        return sessionStore.getOrDefault(state, Map.of("status", "NOT_FOUND"));
    }
}