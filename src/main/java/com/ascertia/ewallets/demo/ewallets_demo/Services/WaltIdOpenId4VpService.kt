package com.ascertia.ewallets.demo.ewallets_demo.services

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import jakarta.annotation.PostConstruct
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.core.io.ClassPathResource
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.text.ParseException
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentHashMap


@Service
class WaltIdOpenId4VpService {

    private val logger = LoggerFactory.getLogger(WaltIdOpenId4VpService::class.java)
    private val objectMapper = ObjectMapper()
    private val sessionStore: MutableMap<String, MutableMap<String, Any>> = ConcurrentHashMap()
    private val requestObjectStore: MutableMap<String, String> = ConcurrentHashMap()
    private lateinit var verifierJWK: ECKey
    private lateinit var x5cChain: List<Base64>

    companion object {
        private const val BASE_URL = "https://test.ewallets.ngrok.app"
        private const val RESPONSE_URI = "$BASE_URL/api/v2/callback"
        private const val clientId = RESPONSE_URI
    }

    data class AuthRequestResult(val deepLink: String, val state: String, val claims: JWTClaimsSet)

    @PostConstruct
    fun init() {
        try {
            val resource = ClassPathResource("verifier.p12")
            val keystore = KeyStore.getInstance("PKCS12")
            resource.inputStream.use { keystore.load(it, "password".toCharArray()) }

            val cert = keystore.getCertificate("verifier") as X509Certificate
            val privateKey = keystore.getKey("verifier", "password".toCharArray()) as ECPrivateKey
            val publicKey = cert.publicKey as ECPublicKey

            x5cChain = listOf(Base64.encode(cert.encoded))

            verifierJWK = ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID("verifier-key-1")
                .x509CertChain(x5cChain)
                .build()

            logger.info("WaltIdOpenId4VpService Ready. Callback: $RESPONSE_URI")
        } catch (e: Exception) {
            logger.error("Failed to init WaltIdOpenId4VpService", e)
        }
    }

    fun createAuthorizationRequest(): AuthRequestResult {
        val nonce = UUID.randomUUID().toString()
        val state = UUID.randomUUID().toString()

        // 1. DCQL Query / Presentation Definition (Claims Set)
        val dcqlQuery = mapOf(
            "credentials" to listOf(
                mapOf(
                    "id" to "pid_sd_jwt",
                    "format" to "dc+sd-jwt",
                    "meta" to mapOf("vct_values" to listOf("urn:eudi:pid:1")),
                    "claims" to listOf(
                        mapOf("path" to listOf("family_name")),
                        mapOf("path" to listOf("given_name"))
                    )
                )
                // Uncomment to add mDoc support if needed
                /*,
                mapOf(
                    "id" to "pid_mdoc",
                    "format" to "mso_mdoc",
                    "meta" to mapOf("doctype_values" to listOf("eu.europa.ec.eudi.pid.1")),
                    "claims" to listOf(
                        mapOf("path" to listOf("eu.europa.ec.eudi.pid.1", "family_name")),
                        mapOf("path" to listOf("eu.europa.ec.eudi.pid.1", "given_name"))
                    )
                )
                */
            )
        )

        // 2. Encryption Key Metadata (Required for JARM)
        val encryptionKey = ECKey.Builder(verifierJWK.curve, verifierJWK.toECPublicKey())
            .keyID(verifierJWK.keyID)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .build()

        val clientMetadata = mapOf(
            "client_name" to "WaltID Demo Verifier",
            "client_uri" to BASE_URL,
            "jwks" to mapOf("keys" to listOf(encryptionKey.toPublicJWK().toJSONObject())),
            "authorization_encrypted_response_alg" to "ECDH-ES",
            "authorization_encrypted_response_enc" to "A128GCM",
            "authorization_encrypted_response_alg_values_supported" to listOf("ECDH-ES"),
            "authorization_encrypted_response_enc_values_supported" to listOf("A128GCM", "A256GCM"),
            "vp_formats_supported" to mapOf(
                "dc+sd-jwt" to mapOf(
                    "sd-jwt_alg_values" to listOf("ES256", "ES384", "ES512"),
                    "kb-jwt_alg_values" to listOf("ES256", "ES384", "ES512")
                ),
                "mso_mdoc" to mapOf(
                    "alg" to listOf("ES256", "ES384", "ES512", "EdDSA")
                )
            )
        )

        // 3. Build the JWT Claims Set
        val claimsSet = JWTClaimsSet.Builder()
            .issuer(RESPONSE_URI)
            .audience("https://self-issued.me/v2")
            .claim("client_id", RESPONSE_URI)
            .claim("client_id_scheme", "redirect_uri")
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("response_uri", "$RESPONSE_URI/$state")
            .claim("nonce", nonce)
            .claim("state", state)
            .claim("dcql_query", dcqlQuery)
            .claim("client_metadata", clientMetadata)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(600)))
            .build()

        // 4. Sign the JWT
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
            .x509CertChain(x5cChain)
            .build()

        val signedRequestObject = SignedJWT(header, claimsSet)
        signedRequestObject.sign(ECDSASigner(verifierJWK))
        val requestJwt = signedRequestObject.serialize()

        // 5. Store the JWT so the wallet can fetch it
        // Use a unique ID for the request object URL
        val requestObjId = UUID.randomUUID().toString()
        requestObjectStore[requestObjId] = requestJwt
        val requestUri = "$BASE_URL/api/v2/request/$requestObjId"

        // Save session state
        sessionStore[state] = mutableMapOf("status" to "PENDING", "nonce" to nonce)

        // 6. Construct the Deep Link
        // The wallet scans this, sees 'request_uri', and calls your server to get the JWT we just created.
        val deepLink = "eudi-openid4vp://?client_id=${
            URLEncoder.encode(
                "redirect_uri:$RESPONSE_URI",
                StandardCharsets.UTF_8
            )
        }&request_uri=${URLEncoder.encode(requestUri, StandardCharsets.UTF_8)}"

        logger.info("Generated Request URL: $deepLink")
        return AuthRequestResult(deepLink, state, claimsSet)
    }


    // --- JARM Decryption (Nimbus) ---
    @Throws(java.lang.Exception::class)
    fun decryptJarmResponse(encryptedResponse: String): MutableMap<String?, Any?> {
        logger.info("Decrypting JARM JWE...")

        val encryptedJWT = EncryptedJWT.parse(encryptedResponse)
        val decrypter = ECDHDecrypter(verifierJWK.toECPrivateKey())

        encryptedJWT.decrypt(decrypter)
        val payload = encryptedJWT.payload

        try {
            val innerJwt = JWTParser.parse(payload.toString())

            if (innerJwt is SignedJWT) {
                logger.info("Inner payload IS a SignedJWT. Extracting claims...")
            } else {
                logger.info("Inner payload is a PlainJWT (Unsigned). Extracting claims...")
            }

            return innerJwt.jwtClaimsSet.toJSONObject()
        } catch (e: ParseException) {
            logger.warn("Inner payload is NOT a JWT string. Assuming direct JSON payload...")
            return payload.toJSONObject()
        }
    }


    fun handleWalletResponse(
        pathId: String?,
        params: Map<String, String>?,
        request: HttpServletRequest
    ): ResponseEntity<String?> {
        logger.info(">>> WALLET CALLBACK HIT (POST) <<<")
        logger.info("pathId: {}", pathId)

        var vpToken: String? = null
        var presentationSubmission: String? = null
        var state: String? = null
        var jarmResponse: String? = null

        try {
            // 1. EXTRACT RAW DATA (Params vs Body)
            // Strategy A: URL Params / Form Data (Standard for direct_post)
            if (params != null && !params.isEmpty()) {
                vpToken = params.get("vp_token")
                presentationSubmission = params.get("presentation_submission")
                state = params.get("state")
                jarmResponse = params.get("response")
            }

            // Strategy B: JSON Body (Fallback for some wallets or custom flows)
            if (vpToken == null && jarmResponse == null && request.getContentType() != null && request.getContentType()
                    .contains("json")
            ) {
                try {
                    val buffer = StringBuilder()
                    val reader = request.getReader()
                    var line: String?
                    while ((reader.readLine().also { line = it }) != null) buffer.append(line)

                    val jsonStr = buffer.toString()
                    if (!jsonStr.isEmpty()) {
                        val json = objectMapper.readValue<MutableMap<String?, Any?>?>(
                            jsonStr,
                            object : TypeReference<MutableMap<String?, Any?>?>() {
                            })
                        if (json.containsKey("vp_token")) vpToken = json.get("vp_token").toString()
                        if (json.containsKey("response")) jarmResponse = json.get("response").toString()
                        if (json.containsKey("state")) state = json.get("state").toString()
                    }
                } catch (e: java.lang.Exception) {
                    println("JSON Body parse failed: " + e.message)
                }
            }

            // If state wasn't in the body, try the path parameter
            if (state == null && pathId != null && !pathId.isEmpty()) {
                state = pathId
            }

            println("Extracted Data - vp_token: " + (vpToken))
            println("Extracted Data - state: " + (state))
            println("Extracted Data - jarmResponse: " + (jarmResponse))

            // 2. PROCESS DATA (JARM Decryption if needed)
            if (jarmResponse != null) {
                println("Status: Encrypted JARM received.")
                try {
                    // DECRYPT using VPService
                    val claims: MutableMap<String?, Any?> = decryptJarmResponse(jarmResponse)

                    // Update state from inside the encrypted token (safest source)
                    if (claims.containsKey("state")) {
                        state = claims.get("state") as String?
                    }

                    // Extract vp_token (Can be String for SD-JWT or List for multiple)
                    val tokenObj = claims.get("vp_token")
                    if (tokenObj is MutableList<*>) {
                        vpToken = tokenObj[0].toString() // Simplified: Take first
                    } else if (tokenObj != null) {
                        vpToken = tokenObj.toString()
                    }

                    val submissionObj = claims.get("presentation_submission")
                    if (submissionObj != null) {
                        presentationSubmission = objectMapper.writeValueAsString(submissionObj)
                    }
                } catch (e: java.lang.Exception) {
                    System.err.println("JARM Decryption Failed: " + e.message)
                    return ResponseEntity.badRequest().body<String?>("Decryption failed: " + e.message)
                }
            }

            // 3. FINAL VALIDATION & HANDOFF
            if (vpToken != null && state != null) {
                println("Status: Valid Token Extracted.")
                println("Token Length: " + vpToken.length)
                println("State: " + state)

                // Pass to Service to update session status
                processWalletResponse(vpToken, presentationSubmission!!, state)

                return ResponseEntity.ok<String?>("Verified")
            }

            System.err.println("Error: No valid 'vp_token' or 'response' found in request.")
            return ResponseEntity.badRequest().body<String?>("Invalid Request: No token found")
        } catch (e: java.lang.Exception) {
            return ResponseEntity.internalServerError().body<String?>("Server Error processing callback")
        }
    }

    fun processWalletResponse(vpToken: String?, presentationSubmission: String?, state: String?) {
        println(">>> PROCESSING RESPONSE for State: " + state + " <<<")

        val extractedData: MutableMap<String?, Any?> = HashMap<String?, Any?>()

        if (vpToken != null) {
            if (vpToken.contains("~")) {
                // Case 1: SD-JWT (Format: IssuerJWT~Disclosure1~Disclosure2~...~EndJWT)
                println("Format: SD-JWT detected. " + vpToken)
                extractSdJwtClaims(vpToken, extractedData)
            } else if (vpToken.startsWith("ey")) {
                // Case 2: Standard JWT
                println("Format: Standard JWT detected.")
                // Add JWT parsing if needed
            } else {
                // Case 3: mDoc (CBOR Base64) - Requires 'jackson-dataformat-cbor'
                println("Format: mDoc (Binary/CBOR) detected.")
                println("NOTE: To parse mDoc, you need 'jackson-dataformat-cbor' dependency.")
                extractedData.put("raw_mdoc", vpToken)
            }
        }

        if (sessionStore.containsKey(state)) {
            val session: MutableMap<String?, Any?> = sessionStore[state] as MutableMap<String?, Any?>
            session.put("status", "RECEIVED")
            session.put("raw_token", vpToken)
            session.put("extracted_data", extractedData) // <--- Store extracted names
            session.put("submission", presentationSubmission)
            logger.info("Session updated. Extracted Data: $extractedData")
        } else {
            logger.warn("Received response for unknown state: $state")
        }
    }

    private fun extractSdJwtClaims(sdJwt: String, output: MutableMap<String?, Any?>) {
        try {
            val parts = sdJwt.split("~".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            println("SD-JWT Parts: " + parts.size)

            // Iterate over disclosures (Indices 1 to N-1)
            for (i in 1..<parts.size) {
                val disclosure = parts[i]
                if (disclosure.isEmpty()) continue

                try {
                    // Disclosures are Base64URL encoded JSON arrays: ["salt", "key", "value"]
                    val decodedBytes = Base64URL.from(disclosure).decode()
                    val jsonStr = String(decodedBytes)

                    // Parse JSON Array
                    if (jsonStr.startsWith("[")) {
                        val node = objectMapper.readTree(jsonStr)
                        if (node.isArray && node.size() >= 3) {
                            val key = node.get(1).asText()
                            val valueNode = node.get(2)

                            // Check for the specific keys you want
                            if ("family_name" == key || "given_name" == key) {
                                println("FOUND CLAIM: " + key + " = " + valueNode.asText())
                                output.put(key, valueNode.asText())
                            }
                        }
                    }
                } catch (e: java.lang.Exception) {
                    // Ignore parts that aren't disclosures (like the Key Binding JWT at the end)
                }
            }
        } catch (e: java.lang.Exception) {
            System.err.println("Error parsing SD-JWT: " + e.message)
        }
    }


    fun getSessionStatus(state: String): Map<String, Any> {
        return sessionStore.getOrDefault(state, mapOf("status" to "NOT_FOUND"))
    }

    fun getRequestJwt(id: String): String? {
        val jwt = requestObjectStore[id]
        if (jwt == null) {
            logger.warn("JWT not found for ID: $id. Available IDs: ${requestObjectStore.keys}")
        }
        return jwt
    }
}