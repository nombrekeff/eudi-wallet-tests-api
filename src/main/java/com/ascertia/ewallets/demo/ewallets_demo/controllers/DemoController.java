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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    @Autowired
    private VPService vpService;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
            String requestJwt = vpService.createAuthorizationRequest();

            byte[] png = generateQRCodePng(requestJwt, 300, 300);

            return ResponseEntity.ok()
                    .contentType(MediaType.IMAGE_PNG)
                    .body(png);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/create-request")
    public ResponseEntity<Map<String, String>> createRequest() {
        try {
            String deepLinkUri = vpService.createAuthorizationRequest();
            return ResponseEntity.ok(Map.of("deepLinkUri", deepLinkUri));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    // NEW ENDPOINT: Serves the Request Object (JWT) to the Wallet
    // This is required for the "request_uri" flow
    @GetMapping(value = "/wallet/request.jwt/{id}", produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> getRequestObject(@PathVariable String id) {
        System.out.println("Received request for Request Object with ID: " + id);
        String jwt = vpService.getRequestJwt(id);
        if (jwt == null) return ResponseEntity.notFound().build();
        System.out.println("" + jwt);
        return ResponseEntity.ok(jwt);
    }

    @RequestMapping(value = "/wallet/callback/**")
    public ResponseEntity<String> walletCallback(
            @RequestParam(required = false) Map<String, String> params,
            HttpServletRequest request
    ) {
        System.out.println(">>> WALLET CALLBACK HIT <<<");
        System.out.println("Method: " + request.getMethod());
        System.out.println("Full Path: " + request.getRequestURI());

        // Extract ID from path if present (everything after /wallet/callback/)
        String pathId = null;
        String uri = request.getRequestURI();
        if (uri.contains("/wallet/callback/")) {
            pathId = uri.substring(uri.indexOf("/wallet/callback/") + 17); // 17 is length of /wallet/callback/
            System.out.println("Extracted Path ID: " + pathId);
        }

        String vpToken = null;
        String presentationSubmission = null;
        String state = null;
        String rawBody = "";

        try {
            // 1. Try to read BODY (for POST/PUT)
            if ("POST".equalsIgnoreCase(request.getMethod()) || "PUT".equalsIgnoreCase(request.getMethod())) {
                StringBuilder buffer = new StringBuilder();
                BufferedReader reader = request.getReader();
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line);
                }
                rawBody = buffer.toString();
                System.out.println("Raw Body Length: " + rawBody.length());
            }

            // 2. STRATEGY A: URL Parameters (GET or Query String)
            if (params != null && !params.isEmpty()) {
                if (params.containsKey("vp_token")) vpToken = params.get("vp_token");
                if (params.containsKey("presentation_submission"))
                    presentationSubmission = params.get("presentation_submission");
                if (params.containsKey("state")) state = params.get("state");
            }

            // 3. STRATEGY B: Form Data (in Body)
            if (vpToken == null && rawBody.contains("vp_token=")) {
                System.out.println("Parsing Body as Form Data...");
                String[] pairs = rawBody.split("&");
                for (String pair : pairs) {
                    String[] kv = pair.split("=");
                    if (kv.length == 2) {
                        String key = java.net.URLDecoder.decode(kv[0], "UTF-8");
                        String value = java.net.URLDecoder.decode(kv[1], "UTF-8");
                        if (key.equals("vp_token")) vpToken = value;
                        if (key.equals("presentation_submission")) presentationSubmission = value;
                        if (key.equals("state")) state = value;
                    }
                }
            }

            // 4. STRATEGY C: JSON Body
            if (vpToken == null && rawBody.trim().startsWith("{")) {
                System.out.println("Parsing Body as JSON...");
                try {
                    Map<String, Object> json = objectMapper.readValue(rawBody, new TypeReference<>() {
                    });
                    if (json.containsKey("vp_token")) vpToken = json.get("vp_token").toString();
                    if (json.containsKey("presentation_submission"))
                        presentationSubmission = json.get("presentation_submission").toString();
                    if (json.containsKey("state")) state = json.get("state").toString();
                } catch (Exception e) {
                    // Not JSON, ignore
                }
            }

            // 5. Fallback: Use Path ID as State if missing
            if (state == null && pathId != null && !pathId.isEmpty()) {
                System.out.println("Using Path ID as State/Nonce fallback.");
                state = pathId;
            }

            if (vpToken != null) {
                System.out.println("SUCCESS: VP Token extracted.");
                vpService.processWalletResponse(vpToken, presentationSubmission, state);
                return ResponseEntity.ok("Received");
            }

            // 6. Handle GET Probe / Redirect
            // If the Wallet is doing a GET (likely a redirect/check), just say OK to prevent errors.
            System.out.println("No token found. Assuming Probe or Redirect Check. Returning 200 OK.");
            return ResponseEntity.ok("Service Ready");
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