# INJI VCI Client

The **Inji VCI Client** is a Kotlin-based library built to simplify credential issuance via [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html) protocol.  
It supports both **Credential Offer** and **Trusted Issuer** flows, with secure proof handling, PKCE support, and custom error handling.


---

## Features

- Request credentials from OID4VCI-compliant credential issuers
- Supports both:
  - Credential Offer Flow.
  - Trusted Issuer Flow.
- Authorization server discovery for both flows
- PKCE-compliant OAuth 2.0 Authorization Code flow (RFC 7636)
- Automatic CNonce + Proof JWT handling
- Well-defined **exception handling** with `VCI-XXX` error codes
- Support for multiple formats:
  - `ldp_vc`
  - `mso_mdoc`

> ⚠️ Consumer of this library is responsible for processing and rendering the credential after it is downloaded.

---

##  Installation

Add the following dependency to your `build.gradle` to include the library from **Maven Central**:

```groovy
implementation "io.mosip:inji-vci-client:0.4.0"
```

##  API Overview

### 1. Request Credential using Credential Offer
```kotlin
fun requestCredentialByCredentialOffer(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        getProofJwt: suspend (accessToken: String, cNonce: String?, issuerMetadata: Map<String, *>?, credentialConfigurationId: String?) -> String,
        getAuthCode: suspend (authorisationEndpoint: String) -> String,
        onCheckIssuerTrust: (suspend (issuerMetadata: Map<String, Any>) -> Boolean)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse?
```
#### Example Use
```kotlin
val response = VCIClient(traceabilityId).requestCredentialByCredentialOffer(
        credentialOffer = offer,
        clientMetadata = ClientMetadata(clientId, redirectUri),
        getTxCode = { inputMode?,description?,length? -> ... },
        getProofJwt = { accessToken, cNonce?, issuerMeta?, credentialConfigurationId? -> ... },
        getAuthCode = { authorizationEndpoint -> ... },
        onCheckIssuerTrust: (suspend (Map<String, Any>) -> Boolean)? = {...},
)
```

### 2. Request Credential from Trusted Issuer
```kotlin
fun requestCredentialFromTrustedIssuer(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        getProofJwt: suspend (
            accessToken: String,
            cNonce: String?,
            issuerMetadata: Map<String, *>?,
            credentialConfigurationId: String?,
        ) -> String,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse?
```

#### Example Use
```kotlin
val response = VCIClient(traceabilityId).requestCredentialFromTrustedIssuer(
        IssuerMetadata = metadata,
        clientMetadata = ClientMetadata(clientId, redirectUri),
        getProofJwt = { accessToken, cNonce?, issuerMeta?, configId? -> ... },
        getAuthCode = { authorizationEndpoint -> ... }
)
```

#### 🔹 Parameters:

| Param                | Type                                                          | Description                                                                      |
|----------------------|---------------------------------------------------------------|----------------------------------------------------------------------------------|
| `credentialOffer`    | `String`                                                      | Offer as embedded JSON or `credential_offer_uri`                                 |
| `clientMetadata`     | `ClientMetadata`                                              | Contains client ID and redirect URI                                              |
| `IssuerMetadata`     | `IssuerMetadata`                                              | Contains Issuer metadata details required for credential request                 |
| `getTxCode`          | `suspend (String?,String?,String?) -> String`                                        | Optional callback function for TX Code (for Pre-Auth flows)                      |
| `getProofJwt`        | `suspend (String, String?, Map<String, *>, String) -> String` | Callback function to prepare proof-jwt for credential request                    |
| `getAuthCode`        | `suspend (String) -> String`                                  | Handles authorization and returns the code (for Authorization flows)             |
| `onCheckIssuerTrust` | `suspend (Map<String, Any>) -> Boolean)?`                     | Optional parameter to implement user-trust based credential download from issuer |
---

---

### 3. Constructing `IssuerMetadata`

Supports both `ldp_vc` and `mso_mdoc`.

#### 🔹 LDP VC Format:
```kotlin
val metadata = IssuerMetadata(
        credentialAudience = "...",
        credentialEndpoint = "...",
        credentialType = arrayOf("VerifiableCredential"),
        credentialFormat = CredentialFormat.LDP_VC
)
```

#### 🔹 MSO mDoc Format:
```kotlin
val metadata = IssuerMetadata(
        credentialAudience = "...",
        credentialEndpoint = "...",
        doctype = "org.iso.18013.5.1.mDL",
        claims = mapOf("given_name" to "John", "family_name" to "Doe"),
        credentialFormat = CredentialFormat.MSO_MDOC
)
```

---

### 4. ClientMetaData

```kotlin
data class ClientMetadata(
    val clientId: String,
    val redirectUri: String
)
```

### 5. ⚠️ Deprecated: Legacy Credential Request

This method is **deprecated** as of v0.4.0.  
Please use `requestCredentialByCredentialOffer` or `requestCredentialFromTrustedIssuer` instead.

```kotlin
@Deprecated(
message = "This method is deprecated as per the new VCI Client library contract. " + "Use requestCredentialByCredentialOffer() or requestCredentialFromTrustedIssuer()",
level = DeprecationLevel.WARNING
)
fun requestCredential(
    issuerMetadata: IssuerMetaData,
    proof: Proof,
    accessToken: String,
): CredentialResponse?
```


##  Security Support

-  **PKCE (Proof Key for Code Exchange)** handled internally (RFC 7636)
-  Supports `S256` code challenge method
-  Secure `c_nonce` binding via proof JWTs

---

##  Error Handling

All exceptions thrown by the library are subclasses of `VCIClientException`.  
They carry structured error codes like `VCI-001`, `VCI-002` etc., to help consumers identify and recover from failures.

| Code    | Exception Type                   | Description                             |
|---------|----------------------------------|-----------------------------------------|
| VCI-001 | `AuthServerDiscoveryException`   | Failed to discover authorization server |
| VCI-002 | `DownloadFailedException`        | Failed to download Credential issuer    |
| VCI-003 | `InvalidAccessTokenException`    | Access token is invalid                 |
| VCI-004 | `InvalidDataProvidedException`   | Required details not provided           |
| VCI-005 | `InvalidPublicKeyException`      | Invalid public key passed metadata      |
| VCI-006 | `NetworkRequestFailedException`  | Network request failed                  |
| VCI-007 | `NetworkRequestTimeoutException` | Network request timed-out               |
| VCI-008 | `OfferFetchFailedException`      | Failed  to fetch credentialOffer        |
| VCI-009 | `IssuerMetadataFetchException`   | Failed to fetch issuerMetadata          |


---

##  Testing

Mock-based tests are available covering:

- Credential download flow (offer + trusted issuer)
- Proof JWT signing callbacks
- Token exchange and CNonce logic

> See `VCIClientTest` for full coverage

---

## Platform Support

- **Kotlin:** 1.7+
- **Android:** API 23+ (Android 6.0 Marshmallow)
- **JVM:** 17 (for Java interop)
- **Gradle:** 8.x+ recommended


Architecture decisions are noted as ADRs [here](https://github.com/mosip/inji-vci-client/tree/master/doc).

Note: The ios library is available [here](https://github.com/mosip/inji-vci-client-ios-swift)

---

## Example App

A complete sample app demonstrating credential issuance flows, proof JWT signing, and error handling with `VCIClient` is available here:

[👉 Example Kotlin App Repository](https://github.com/mosip/inji-vci-client/tree/release-0.4.x/kotlin/example)


> Use the example app to quickly get started and see the library in action.

---