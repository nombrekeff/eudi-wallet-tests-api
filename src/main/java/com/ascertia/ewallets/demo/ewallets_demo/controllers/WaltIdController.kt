package com.ascertia.ewallets.demo.ewallets_demo.controllers

import com.ascertia.ewallets.demo.ewallets_demo.services.WaltIdOpenId4VpService
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.client.j2se.MatrixToImageWriter
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO

@RestController
@RequestMapping("/api/v2")
class WaltIdController(
    private val waltIdService: WaltIdOpenId4VpService,
    private val objectMapper: ObjectMapper
) {

    private val logger = LoggerFactory.getLogger(WaltIdController::class.java)

    // 1. Create Request & Return Data
    @GetMapping("/create-request")
    fun createRequest(): ResponseEntity<WaltIdOpenId4VpService.AuthRequestResult> {
        return try {
            val result = waltIdService.createAuthorizationRequest()
            ResponseEntity.ok(result)
        } catch (e: Exception) {
            logger.error("Error creating request", e)
            ResponseEntity.internalServerError().build()
        }
    }

    // 2. Create Request & Return QR Code Image
    @GetMapping(value = ["/create-request-qr"], produces = [MediaType.IMAGE_PNG_VALUE])
    fun createRequestQr(): ResponseEntity<ByteArray> {
        return try {
            val result = waltIdService.createAuthorizationRequest()
            val deepLink = result.deepLink
            logger.info("[WaltID] Generated DeepLink: $deepLink")

            val matrix = MultiFormatWriter().encode(deepLink, BarcodeFormat.QR_CODE, 300, 300)
            val image = MatrixToImageWriter.toBufferedImage(matrix)
            val baos = ByteArrayOutputStream()
            ImageIO.write(image, "PNG", baos)

            ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(baos.toByteArray())
        } catch (e: Exception) {
            logger.error("Error creating QR code", e)
            ResponseEntity.internalServerError().build()
        }
    }

    // 3. Serve the Request JWT (if accessed via reference)
    // Note: If your request_uri points here, the wallet calls this.
    // Since we are using 'direct_post' mostly, we might not need a separate JWT endpoint if the JWT is embedded,
    // BUT if the URI passed to the wallet is a reference, we need to serve the JWT.
    // Our service currently puts the JWT in an object store.
    // If you need to serve it, we'd need to expose that from the service.
    // For now, assuming standard flow or embedded.
    // If you need to fetch by ID:

    @GetMapping("/request/{id}", produces = ["application/oauth-authz-req+jwt"])
    fun getRequestObject(@PathVariable id: String): ResponseEntity<String> {
        logger.info("[WaltID] Serving Request JWT for ID: $id")
        val jwt = waltIdService.getRequestJwt(id) // Assuming you add this method to service
        return if (jwt != null) ResponseEntity.ok(jwt) else ResponseEntity.notFound().build()
    }


    // 4. Callback Handler
    @PostMapping("/callback/{id}")
    fun walletCallback(
        @PathVariable id: String,
        @RequestParam(required = false) params: Map<String, String>?,
        request: HttpServletRequest
    ): ResponseEntity<String?> {
        logger.info("[WaltID] Received callback for ID: $id with params: $params")
        return waltIdService.handleWalletResponse(id, params, request)
    }

    // 5. Check Status
    @GetMapping("/check-status")
    fun checkStatus(@RequestParam state: String): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(waltIdService.getSessionStatus(state))
    }
}