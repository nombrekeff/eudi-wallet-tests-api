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
import java.util.List;
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

    // --- UNIVERSAL CALLBACK HANDLER (POST ONLY) ---
    @PostMapping(value = "/wallet/callback/**")
    public ResponseEntity<String> walletCallback(
            @RequestParam(required = false) Map<String, String> params,
            HttpServletRequest request
    ) {
        System.out.println(">>> WALLET CALLBACK HIT (POST) <<<");
        System.out.println("Full Path: " + request.getRequestURI());

        String pathId = null;
        String uri = request.getRequestURI();
        // Extract ID from path if present (e.g. /wallet/callback/{state})
        if (uri.contains("/wallet/callback/")) {
            pathId = uri.substring(uri.indexOf("/wallet/callback/") + 17);
        }

        String vpToken = null;
        String presentationSubmission = null;
        String state = null;
        String jarmResponse = null;

        try {
            // 1. EXTRACT RAW DATA (Params vs Body)
            // Strategy A: URL Params / Form Data (Standard for direct_post)
            if (params != null && !params.isEmpty()) {
                vpToken = params.get("vp_token");
                presentationSubmission = params.get("presentation_submission");
                state = params.get("state");
                jarmResponse = params.get("response");
            }

            // Strategy B: JSON Body (Fallback for some wallets or custom flows)
            if (vpToken == null && jarmResponse == null && request.getContentType() != null && request.getContentType().contains("json")) {
                try {
                    StringBuilder buffer = new StringBuilder();
                    BufferedReader reader = request.getReader();
                    String line;
                    while ((line = reader.readLine()) != null) buffer.append(line);

                    String jsonStr = buffer.toString();
                    if (!jsonStr.isEmpty()) {
                        Map<String, Object> json = objectMapper.readValue(jsonStr, new TypeReference<>() {
                        });
                        if (json.containsKey("vp_token")) vpToken = json.get("vp_token").toString();
                        if (json.containsKey("response")) jarmResponse = json.get("response").toString();
                        if (json.containsKey("state")) state = json.get("state").toString();
                    }
                } catch (Exception e) {
                    System.out.println("JSON Body parse failed: " + e.getMessage());
                }
            }

            // If state wasn't in the body, try the path parameter
            if (state == null && pathId != null && !pathId.isEmpty()) {
                state = pathId;
            }

            System.out.println("Extracted Data - vp_token: " + (vpToken));
            System.out.println("Extracted Data - state: " + (state));
            System.out.println("Extracted Data - jarmResponse: " + (jarmResponse));

            // 2. PROCESS DATA (JARM Decryption if needed)
            if (jarmResponse != null) {
                System.out.println("Status: Encrypted JARM received.");
                try {
                    // DECRYPT using VPService
                    Map<String, Object> claims = vpService.decryptJarmResponse(jarmResponse);

                    // Update state from inside the encrypted token (safest source)
                    if (claims.containsKey("state")) {
                        state = (String) claims.get("state");
                    }

                    // Extract vp_token (Can be String for SD-JWT or List for multiple)
                    Object tokenObj = claims.get("vp_token");
                    if (tokenObj instanceof List) {
                        vpToken = ((List<?>) tokenObj).get(0).toString(); // Simplified: Take first
                    } else if (tokenObj != null) {
                        vpToken = tokenObj.toString();
                    }

                    Object submissionObj = claims.get("presentation_submission");
                    if (submissionObj != null) {
                        presentationSubmission = objectMapper.writeValueAsString(submissionObj);
                    }
                } catch (Exception e) {
                    System.err.println("JARM Decryption Failed: " + e.getMessage());
                    return ResponseEntity.badRequest().body("Decryption failed: " + e.getMessage());
                }
            }

            // 3. FINAL VALIDATION & HANDOFF
            if (vpToken != null && state != null) {
                System.out.println("Status: Valid Token Extracted.");
                System.out.println("Token Length: " + vpToken.length());
                System.out.println("State: " + state);

                // Pass to Service to update session status
                vpService.processWalletResponse(vpToken, presentationSubmission, state);

                return ResponseEntity.ok("Verified");
            }

            System.err.println("Error: No valid 'vp_token' or 'response' found in request.");
            return ResponseEntity.badRequest().body("Invalid Request: No token found");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Server Error processing callback");
        }
    }

    @GetMapping("/check-status")
    public ResponseEntity<Map<String, Object>> checkStatus(@RequestParam String state) {
        return ResponseEntity.ok(vpService.getSessionStatus(state));
    }
}