package com.ascertia.ewallets.demo.ewallets_demo.controllers;

import com.ascertia.ewallets.demo.ewallets_demo.services.VPService;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    @Autowired
    private VPService vpService;

    // --- QR CODE GENERATION ---
    private static byte[] generateQRCodePng(String text, int width, int height) throws Exception {
        BitMatrix matrix = new MultiFormatWriter().encode(text, BarcodeFormat.QR_CODE, width, height);
        BufferedImage image = MatrixToImageWriter.toBufferedImage(matrix);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "PNG", baos);
        return baos.toByteArray();
    }

    @GetMapping(value = "/create-request-qr", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> createRequestQR() {
        try {
            VPService.AuthRequestResult result = vpService.createAuthorizationRequest();
            String deepLink = result.deepLink();

            byte[] png = generateQRCodePng(deepLink, 300, 300);
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(png);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping(value = "/create-request")
    public ResponseEntity<VPService.AuthRequestResult> createRequest() {
        try {
            return ResponseEntity.ok(vpService.createAuthorizationRequest());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }


    @GetMapping(value = "/wallet/request/{id}", produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> getRequestObject(@PathVariable String id) {
        System.out.println("Wallet is fetching JWT ID: " + id);
        String jwt = vpService.getRequestJwt(id);

        if (jwt == null) {
            System.err.println("ERROR: JWT not found for ID: " + id);
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(jwt);
    }

    @PostMapping(value = "/wallet/callback/{id}")
    public ResponseEntity<String> walletCallback(
            @RequestParam(required = false) Map<String, String> params,
            @PathVariable String id,
            HttpServletRequest request
    ) {
        return vpService.handleWalletResponse(id, params, request);
    }


    @GetMapping("/check-status")
    public ResponseEntity<Map<String, Object>> checkStatus(@RequestParam String state) {
        return ResponseEntity.ok(vpService.getSessionStatus(state));
    }
}