package com.ascertia.ewallets.demo.ewallets_demo.controllers;

import com.ascertia.ewallets.demo.ewallets_demo.Services.VPService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    @Autowired
    private VPService vpService;

    private final ObjectMapper objectMapper = new ObjectMapper();

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
            System.out.println("Generated DeepLink: " + deepLink);
            byte[] png = generateQRCodePng(deepLink, 300, 300);
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(png);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping(value = "/create-request")
    public ResponseEntity<VPService.AuthRequestResult> createRequest() {
        try {
            return ResponseEntity.ok(vpService.createAuthorizationRequest());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }


    // --- WALLET ENDPOINTS ---

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

    // --- UNIVERSAL CALLBACK HANDLER ---
    @RequestMapping(value = "/wallet/callback/**")
    public ResponseEntity<String> walletCallback(
            @RequestParam(required = false) Map<String, String> params,
            HttpServletRequest request
    ) {
        System.out.println(">>> WALLET CALLBACK HIT <<<");
        System.out.println("Method: " + request.getMethod());
        System.out.println("Full Path: " + request.getRequestURI());

        String pathId = null;
        String uri = request.getRequestURI();
        if (uri.contains("/wallet/callback/")) {
            pathId = uri.substring(uri.indexOf("/wallet/callback/") + 17);
        }

        String vpToken = null;
        String presentationSubmission = null;
        String state = null;

        // JARM Support (Encrypted Response)
        String jarmResponse = null;

        try {
            // STRATEGY 1: Params (Query or Form Body parsed by Spring)
            if (params != null && !params.isEmpty()) {
                if (params.containsKey("vp_token")) {
                    vpToken = params.get("vp_token");
                    presentationSubmission = params.get("presentation_submission");
                    state = params.get("state");
                } else if (params.containsKey("response")) {
                    // This means the Wallet sent an Encrypted JARM response
                    jarmResponse = params.get("response");
                    state = params.get("state"); // State might be outside
                }
            }

            // STRATEGY 2: JSON Body
            if (vpToken == null && jarmResponse == null && request.getContentType() != null && request.getContentType().contains("json")) {
                try {
                    StringBuilder buffer = new StringBuilder();
                    BufferedReader reader = request.getReader();
                    String line;
                    while ((line = reader.readLine()) != null) buffer.append(line);
                    String rawBody = buffer.toString();

                    if (!rawBody.isEmpty()) {
                        Map<String, Object> json = objectMapper.readValue(rawBody, new TypeReference<>() {});
                        if (json.containsKey("vp_token")) vpToken = json.get("vp_token").toString();
                        if (json.containsKey("response")) jarmResponse = json.get("response").toString();
                        if (json.containsKey("state")) state = json.get("state").toString();
                    }
                } catch (Exception e) {
                    System.out.println("JSON parse skipped: " + e.getMessage());
                }
            }

            // Fallback State
            if (state == null && pathId != null && !pathId.isEmpty()) {
                state = pathId;
            }

            // --- FINAL DECISION ---
            if (vpToken != null) {
                System.out.println("SUCCESS: Plaintext VP Token extracted.");
                vpService.processWalletResponse(vpToken, presentationSubmission, state);
                return ResponseEntity.ok("Received Plaintext");
            }
            else if (jarmResponse != null) {
                System.out.println("SUCCESS: Encrypted JARM Response received!");
                System.out.println("Response Length: " + jarmResponse.length());
                System.out.println("NOTE: You need JARM Decryption logic to read this.");
                // For now, we consider this a success (the wallet sent data)
                vpService.processWalletResponse("ENCRYPTED_JARM_DATA", "ENCRYPTED", state);
                return ResponseEntity.ok("Received Encrypted");
            }
            else if ("GET".equalsIgnoreCase(request.getMethod())) {
                System.out.println("Probe Check (GET). Returning 200 OK.");
                return ResponseEntity.ok("Service Ready");
            }
            else {
                System.err.println("ERROR: POST received but no 'vp_token' or 'response' found.");
                return ResponseEntity.badRequest().body("Missing token or response");
            }

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error processing callback");
        }
    }

    @GetMapping("/check-status")
    public ResponseEntity<Map<String, Object>> checkStatus(@RequestParam String state) {
        return ResponseEntity.ok(vpService.getSessionStatus(state));
    }
}