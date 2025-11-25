# OpenID4VP Verifier PoC (EUDI Wallet)

This Proof of Concept (PoC) demonstrates a Spring Boot-based Verifier that implements the OpenID for Verifiable Presentations (OpenID4VP) protocol. It is designed to request and verify digital credentials (such as PIDs) from EUDI-compliant mobile wallets.

This implementation supports:
*   **Query Language**: DCQL (Digital Credentials Query Language)
*   **Formats**: SD-JWT (`dc+sd-jwt`) and ISO mDoc (`mso_mdoc`, not yet supported herin this poc)
*   **Security**: JARM (JWT Secured Authorization Response Mode) with ECDH-ES encryption.

## Prerequisites

*   Java 21 (or compatible JDK)
*   Maven (Wrapper included)
*   Ngrok (Required for public internet access to localhost)
*   EUDI Wallet App (iOS or Android)

## Setup Guide

1.  **Clone and Configure**
    Clone this repository to your local machine.

2.  **Start Ngrok (Critical)**
    The wallet on your mobile phone must be able to reach your local server. We use Ngrok to create a secure tunnel.
    ```bash
    ngrok http 8080
    ```
    Copy the HTTPS URL (e.g., `https://1234-56-78.ngrok-free.app`). You will need this for the configuration.
> ⚠️ Ideally, use a paid Ngrok plan to reserve a static URL. Free plans may change the URL on each restart.
> ⚠️ If you change the URL, you will need to regenerate the Verifier Identity Certificate in step 3.

3.  **Generate the Verifier Identity Certificate**
    The Verifier needs an Identity Certificate to sign requests and decrypt responses. The Subject Alternative Name (SAN) of this certificate **MUST** match your Ngrok callback URL exactly.

    Run this command in your project root (replace the URL with your actual Ngrok URL):
    ```bash
    keytool -genkeypair \
    -alias verifier \
    -keyalg EC \
    -keysize 256 \
    -sigalg SHA256withECDSA \
    -storetype PKCS12 \
    -keystore src/main/resources/verifier.p12 \
    -storepass password \
    -dname "CN=EUDI Demo Verifier" \
    -ext "SAN=URI:https://YOUR-NGROK-ID.ngrok-free.app/api/wallet/callback" \
    -ext "KeyUsage=digitalSignature,keyEncipherment,keyAgreement" \
    -validity 365
    ```
    **Note**: If you restart Ngrok and get a new URL, you **MUST** re-run this command to regenerate the certificate with the new URL.

4.  **Update Configuration Code**
    Open `src/main/java/com/ascertia/ewallets/demo/ewallets_demo/Services/VPService.java`.
    Update the `BASE_URL` constant to match your Ngrok URL:
    ```java
    // src/main/java/com/ascertia/ewallets/demo/ewallets_demo/Services/VPService.java

    // TODO: Change this to your actual Ngrok/Server URL
    private static final String BASE_URL = "https://YOUR-NGROK-ID.ngrok-free.app";
    ```

## How to Run

1.  **Build and Start the App**:
    ```bash
    ./mvnw spring-boot:run
    ```

2.  **Generate a Request**:
    Open your browser and navigate to:
    `http://localhost:8080/api/create-request-qr`

    This will display a QR Code containing the OpenID4VP Authorization Request.

## Wallet Testing

To test the PoC, you need a compliant EUDI Wallet.

1.  **Install the Wallet**
    *   **iOS**: https://eu-digital-identity-wallet.github.io/Test/Wallet%20Application/iOS
    *   **Android**: https://eu-digital-identity-wallet.github.io/Test/Wallet%20Application/Android

2.  **Load Test Credentials**
    *  Open the wallet and create a new the "PID" (Person Identification Data) test credential. In the **sd-jwt VC** format.
    *  Ensure the credential contains at least the `family_name` and `given_name` claims.
    *  Save the credential in the wallet.


3.  **Scan and Verify**
    *   Open the Wallet app.
    *   Tap `Scan`.
    *   Scan the QR code displayed on your browser (`http://localhost:8080/api/create-request-qr`).
    *   The wallet should show a consent screen: "Demo Verifier wants to access your Family Name and Given Name".
    *   Tap `Share` / `Confirm`.
    *   Watch your Java application console logs. You should see:
        ```
        Decrypting JARM JWE...
        Status: Valid Token Extracted.
        FOUND CLAIM: family_name = ...
        ```

## Architecture & Caveats

### The "Invalid Client" Error
If the wallet says "Invalid Client" or "Untrusted Issuer", check:
*   Does the URL in `VPService.java` match the Ngrok URL?
*   Did you regenerate the `verifier.p12` with that exact URL in the SAN field?
*   Is `client_id_scheme` set to `redirect_uri`?

### The "Decryption Failed" Error
If the server fails to decrypt the response:
*   Ensure the `verifier.p12` was generated with `-ext "KeyUsage=...,keyEncipherment,keyAgreement"`.
*   The wallet might be sending raw JSON instead of a nested JWT. The code attempts to handle this fallback automatically.

### Supported Formats
This PoC requests SD-JWT by default. To test mDoc (Mobile Driver's License format), uncomment the `mdocQuery` in `VPService.java` -> `createDcqlQuery`. Note that mDoc is binary (CBOR) and will show as raw data in the logs unless you add a CBOR parser.