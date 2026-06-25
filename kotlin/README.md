# INJI VCI Client

The **Inji VCI Client** is a Kotlin-based library built to simplify credential issuance via [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) protocol.
It supports **Issuer Initiated (Credential Offer)** and **Wallet Initiated (Trusted Issuer)** flows, with secure proof handling, PKCE support, and custom error handling.

---

## Specifications supported

The implementation follows
- OpenID for Verifiable Credential Issuance 1.0
- OpenID for Verifiable Credential Issuance draft 13 compatibility for issuers that still expose the older metadata and request/response format

## Features

- Request credentials from OID4VCI-compliant credential issuers
- Supports both:
  - Issuer Initiated Flow (Credential Offer Flow).
  - Wallet Initiated Flow (Trusted Issuer Flow).
- Authorization server discovery for both flows
- PKCE-compliant OAuth 2.0 Authorization Code flow (RFC 7636)
  - PKCE session is managed internally by the library
- Well-defined **exception handling** with `VCI-XXX` error codes (see more on [this](#-error-handling))
- Support for multiple Credential formats:
  - `ldp_vc`
  - `mso_mdoc`
  - `vc+sd-jwt` / `dc+sd-jwt`

[//]: # (The reference for PDI is intentionally pointing to the common doc folder in the root of the repository, as the PDI support and its documentation are common for both the Kotlin and Swift libraries.)
- Presentation During Issuance (PDI) support for both download flows (For more details on PDI support, please refer to the [Presentation During Issuance documentation](../doc/presentation-during-issuance-support.md))

> Consumer of this library is responsible for processing and rendering the credential after it is downloaded.

## Library implementations available in:
This library is officially supported and available in both Kotlin and Swift, ensuring seamless integration across Android and iOS platforms. The references for both implementations are provided below:

* [Kotlin](.)
* [Swift](https://github.com/inji/inji-vci-client-ios-swift)

---

## 📦 Installation

Add the following dependency to your `build.gradle` to include the library from **Maven Central**:

```groovy
implementation "io.inji:inji-vci-client:1.0.0"
```

## What's New in 1.0.0

Version `1.0.0` adds support for the final **OpenID for Verifiable Credential Issuance 1.0** specification while retaining backward compatibility with OID4VCI draft 13. The highlights below cover everything added since `0.7.0`:

- **OID4VCI 1.0 support with retained draft 13 support** - The library auto-detects the spec version of the issuer from its metadata and builds the credential request accordingly, so a single integration works against both 1.0 and draft 13 issuers.
- **Credential download methods renamed (and now return multiple credentials)** - `fetchCredentialUsingCredentialOffer` and `fetchCredentialFromTrustedIssuer` are now `fetchCredentialsUsingCredentialOffer` and `fetchCredentialsFromTrustedIssuer`.
- **New `getProofs` callback** - The single-proof `getProofJwt` callback is replaced by `getProofs`, which returns a `CredentialRequestProofs` object and allows supplying one or more proofs in a single credential request, as per OID4VCI 1.0.
- **`CredentialResponse` now exposes a `credentials` list** - Instead of a single `credential` field, the response carries a `credentials` list (`List<CredentialItem>`), aligning with the OID4VCI 1.0 credential response structure.
- **Legacy APIs removed** - `requestCredentialByCredentialOffer`, `requestCredentialFromTrustedIssuer`, and `requestCredential` (along with the `IssuerMetaData` DTO) have been removed. Migrate to the `fetchCredentials*` methods.
- **Structured error handling** - `VCIClientException` now carries `issuerErrorCode` and `issuerErrorDescription` alongside `code` and `message`, and `code` resolves to the root error code across the cause chain, so consumers can distinguish library failures from issuer/authorization-server error payloads (see [Error Handling](#-error-handling)).
- **Issuer identity validation** - Issuer metadata fetches now validate that the `credential_issuer` returned by the well-known endpoint matches the requested issuer, per [OID4VCI Section 13.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-13.5).

## 🏗️ Construction of VCIClient instance

- The `VCIClient` is constructed with a `traceabilityId` which is used to track the session and traceability of the credential request.

```kotlin
val traceabilityId = "sample-trace-id"
val vciClient = VCIClient(traceabilityId)
```

#### Parameters

| Name            | Type   | Required | Default Value | Description                          |
|-----------------|--------|----------|---------------|--------------------------------------|
| traceabilityId  | String | Yes      | N/A           | Unique identifier for the session    |

## 📖 API Overview

### 1. Obtain Issuer Metadata

Retrieve the issuer metadata from the credential issuer's well-known endpoint.

#### Parameters

| Name             | Type   | Required | Default Value | Description                  |
|------------------|--------|----------|---------------|------------------------------|
| credentialIssuer | String | Yes      | N/A           | URI of the Credential Issuer |

#### Returns

`IssuerMetadata` object containing details like `credential_endpoint`, `credential_issuer`, and other IssuerMetadata information from the well-known endpoint of Credential Issuer, which can be used by the consumer to display Issuer information, etc.

> Note: This method does not parse the metadata, it simply returns the raw Network response of well-known endpoint as a `Map<String, Any>`.

#### Example Usage

```kotlin
val issuerMetadata : Map<String, Any> = VCIClient(traceabilityId).getIssuerMetadata(
    credentialIssuer = "https://example.com/issuer"
)

//The response looks similar to this
mapOf(
  "credential_issuer" to "https://example.com/issuer",
  "credential_endpoint" to "https://example.com/issuer/credential",
)
```

### 2. Obtain Credential Configurations Supported

Retrieve credential configurations supported for given issuer from its well-known endpoint.

#### Parameters

| Name             | Type   | Required | Default Value | Description                  |
|------------------|--------|----------|---------------|------------------------------|
| credentialIssuer | String | Yes      | N/A           | URI of the Credential Issuer |

#### Returns
Map of `credential_configurations_supported` objects containing details like `format`, `scope` and other configuration
information from the well-known endpoint of Credential Issuer, which can be used by the consumer to display supported
credential types, etc.

> Note: This method does not parse the metadata, it simply returns the raw Network response of well-known endpoint as a `Map<String, Any>`.

#### Example Usage

```kotlin
val credentialConfigurationsSupported : Map<String, Any> = VCIClient(traceabilityId).getCredentialConfigurationsSupported(
    credentialIssuer = "https://example.com/issuer"
)

//The response looks similar to this
mapOf(
  "credentialConfigId-1" to mapOf(
    "format" to "ldp_vc",
    "credential_definition" to mapOf(
        "type" to listOf("VerifiableCredential", "ExampleCredential")
    )
  ),
  "credentialConfigId-2" to mapOf(
    "format" to "mso_mdoc",
    "doctype" to "org.iso.18013.5.1.mDL"
  )
)
```

### 3. Request Credential

### 3.1 Request Credential using Credential Offer

#### fetchCredentialsUsingCredentialOffer

- Method: `fetchCredentialsUsingCredentialOffer`
- This method allows you to fetch credential(s) using a credential offer, which can be either an embedded JSON or a URI pointing to the credential offer.
- It supports both **Pre-Authorization** and **Authorization** flows.
- The library handles the PKCE flow internally.
- User-trust based credential download supported through onCheckIssuerTrust callback.
- This method is the recommended way to request credential using credential offer.

##### Parameters

| Name                    | Type                     | Required | Default Value | Description                                                                                                                                                            |
|-------------------------|--------------------------|----------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialOffer         | String                   | Yes      | N/A           | Credential offer as embedded JSON or `credential_offer_uri`                                                                                                            |
| clientMetadata          | ClientMetadata           | Yes      | N/A           | Contains client ID and redirect URI                                                                                                                                    |
| getTxCode               | TxCodeCallback           | No       | N/A           | Optional callback function for TX Code (for Pre-Auth flows)                                                                                                            |
| authorizations          | List<AuthorizationMethod>| Yes      | N/A           | Callback functions list to handle authorization and return the resultant authorization response (for Authorization flows) [see authorization details](#authorizations) |
| getTokenResponse        | TokenResponseCallback    | Yes      | N/A           | Callback function to exchange Authorization Grant with Access Token response                                                                                           |
| getProofs               | ProofsCallback           | Yes      | N/A           | Callback function to prepare the proof(s) for the Credential Request, returning a `CredentialRequestProofs`                                                            |
| onCheckIssuerTrust      | CheckIssuerTrustCallback | No       | null          | Callback function to get user trust with the Credential Issuer                                                                                                         |
| downloadTimeoutInMillis | Long                     | No       | 10000         | Download timeout set for Credential Request call with Credential Issuer (defaults to 10000 ms)                                                                         |

##### Returns

An instance of `CredentialResponse` containing:

| Name                      | Type                  | Description                                                                                                  |
|---------------------------|-----------------------|--------------------------------------------------------------------------------------------------------------|
| credentials               | List<CredentialItem>  | The credential(s) downloaded from the Issuer. Each `CredentialItem` exposes a `credential` (`JsonElement`)   |
| credentialConfigurationId | String                | The identifier of the respective supported credential from well-known response                               |
| credentialIssuer          | String                | URI of the Credential Issuer                                                                                  |

##### Example usage

```kotlin
val credentialResponse: CredentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(
  credentialOffer = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fsample-issuer.com%2Fcredential-offer",
  clientMetadata = ClientMetadata(clientId = "sample-client-id", redirectUri = "https://sample-wallet.com/callback"),
  getTxCode = object : TxCodeCallback {
    override suspend fun invoke(p1: String?, p2: String?, p3: Int?): String {
      // Handle the transaction code retrieval logic here
      val txCode = "sampleTxCode"
      return txCode
    }
  },
  authorizations = listOf(
      // Presentation During Issuance flow for authorization
      AuthorizationMethod.PresentationDuringIssuance(
          selectCredentialsForPresentation = selectCredentialsForPresentationCallback(),
          signVerifiablePresentation = signVerifiablePresentationCallback()
      ),
      // Redirect to Web flow for Web view authorization
      AuthorizationMethod.RedirectToWeb(openWebPage = openWebPageCallback())
  ),
  getTokenResponse = object : TokenResponseCallback {
    override suspend fun invoke(tokenRequest: TokenRequest): TokenResponse {
      // Handle the token response retrieval logic here
      //Exchange authorization code for access token
      return TokenResponse(
        accessToken = "sampleAccessToken",
        cNonce = "sampleNonce",
        tokenType = "Bearer",
        expiresIn = 3600,
        cNonceExpiresIn = 3600,
      )
    }
  },
  getProofs = object : ProofsCallback {
    override suspend fun invoke(
      credentialIssuer: String,
      nonce: String?,
      proofSigningAlgorithmsSupported: List<String>
    ): CredentialRequestProofs {
      // Prepare and sign one or more proof JWTs with the private key as per the proofSigningAlgorithmsSupported
      return CredentialRequestProofs(proofs = listOf("sampleProofJwt"))
    }
  },
  onCheckIssuerTrust = object : CheckIssuerTrustCallback {
    override suspend fun invoke(
      credentialIssuer: String,
      issuerDisplay: List<Map<String, Any>>
    ): Boolean {
      // Handle the issuer trust check logic here
      return true // Assume the issuer is trusted for this example
    }
  },
  downloadTimeoutInMillis = 10000
)

//Consider the credential is a Driver's license credential (credential format `mso_mdoc`)
val credentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(credentialOffer, clientMetadata, getTxCode, authorizations, getTokenResponse, getProofs, onCheckIssuerTrust, downloadTimeoutInMillis)
credentialResponse.credentials // List<CredentialItem>; each item's `credential` is a JsonElement. eg - JsonPrimitive("omdk...t")
credentialResponse.credentialConfigurationId // eg - "DriversLicense"
credentialResponse.credentialIssuer // eg - "https://sample-issuer.com"
```

#### requestCredentialByCredentialOffer (removed in 1.0)

> ⚠️ **Removed in 1.0**: `requestCredentialByCredentialOffer` (deprecated since `0.7.0`) has been removed. Use [`fetchCredentialsUsingCredentialOffer`](#fetchcredentialsusingcredentialoffer) instead, which supports both Pre-Authorization and Authorization flows along with the different authorization methods (Redirect to Web / Presentation During Issuance).

### 3.2 Request Credential from Trusted Issuer

#### fetchCredentialsFromTrustedIssuer
- Method: `fetchCredentialsFromTrustedIssuer`
- It supports **Authorization** flow.
- The library handles the PKCE flow internally.

#### Parameters

| Name                      | Type                  | Required | Default Value | Description                                                                                                                                                                               |
|---------------------------|-----------------------|----------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialIssuer          | String                | Yes      | N/A           | URI of the Credential Issuer                                                                                                                                                              |
| credentialConfigurationId | String                | Yes      | N/A           | Identifier of the respective supported credential from well-known response                                                                                                                |
| clientMetadata            | ClientMetadata        | Yes      | N/A           | Contains client ID and redirect URI                                                                                                                                                       |
| getTokenResponse          | TokenResponseCallback | Yes      | N/A           | Callback function to exchange Authorization Grant with Access Token response                                                                                                              |
| authorizations            | List<AuthorizationMethod> | Yes  | N/A           | Callback functions list to handle authorization and return the resultant authorization response (for Authorization flows) [see authorization details](#authorizations)                     |
| getProofs                 | ProofsCallback        | Yes      | N/A           | Callback function to prepare the proof(s) for the Credential Request, returning a `CredentialRequestProofs`                                                                               |
| downloadTimeoutInMillis   | Long                  | No       | 10000         | Download timeout set for Credential Request call with Credential Issuer (defaults to 10000 ms)                                                                                            |

#### Returns

An instance of `CredentialResponse` containing:

| Name                      | Type                  | Description                                                                                                  |
|---------------------------|-----------------------|--------------------------------------------------------------------------------------------------------------|
| credentials               | List<CredentialItem>  | The credential(s) downloaded from the Issuer. Each `CredentialItem` exposes a `credential` (`JsonElement`)   |
| credentialConfigurationId | String                | The identifier of the respective supported credential from well-known response                               |
| credentialIssuer          | String                | URI of the Credential Issuer                                                                                  |

#### Example usage

```kotlin
val credentialResponse: CredentialResponse = vciClient.fetchCredentialsFromTrustedIssuer(
  credentialIssuer = "https://sample-issuer.com",
  credentialConfigurationId = "DriversLicense",
  clientMetadata = ClientMetadata(
    clientId = "sample-client-id",
    redirectUri = "https://sample-wallet.com/callback"
  ),
  getTokenResponse = object : TokenResponseCallback {
    override suspend fun invoke(tokenRequest: TokenRequest): TokenResponse {
      // Handle the token response retrieval logic here
      //Exchange authorization code for access token
      return TokenResponse(
        accessToken = "sampleAccessToken",
        cNonce = "sampleNonce",
        tokenType = "Bearer",
        expiresIn = 3600,
        cNonceExpiresIn = 3600,
      )
    }
  },
  authorizations = listOf(
    // Presentation During Issuance flow for authorization
    AuthorizationMethod.PresentationDuringIssuance(
        selectCredentialsForPresentation = selectCredentialsForPresentationCallback(),
        signVerifiablePresentation = signVerifiablePresentationCallback()
    ),
    // Redirect to Web flow for Web view authorization
    AuthorizationMethod.RedirectToWeb(openWebPage = openWebPageCallback())
  ),
  getProofs = object : ProofsCallback {
    override suspend fun invoke(
      credentialIssuer: String,
      nonce: String?,
      proofSigningAlgorithmsSupported: List<String>
    ): CredentialRequestProofs {
      // Prepare and sign one or more proof JWTs with the private key as per the proofSigningAlgorithmsSupported
      return CredentialRequestProofs(proofs = listOf("sampleProofJwt"))
    }
  },
  downloadTimeoutInMillis = 10000
)

//Consider the credential is a Driver's license credential (credential format `mso_mdoc`)
val mdocCredentialResponse = vciClient.fetchCredentialsFromTrustedIssuer(credentialIssuer, credentialConfigurationId, clientMetadata, getTokenResponse, authorizations, getProofs, downloadTimeoutInMillis)
credentialResponse.credentials // List<CredentialItem>; each item's `credential` is a JsonElement. eg - JsonPrimitive("omdk...t")
credentialResponse.credentialConfigurationId // eg - "DriversLicense"
credentialResponse.credentialIssuer // eg - "https://sample-issuer.com"
```

#### requestCredentialFromTrustedIssuer (removed in 1.0)

> ⚠️ **Removed in 1.0**: `requestCredentialFromTrustedIssuer` (deprecated since `0.7.0`) has been removed. Use [`fetchCredentialsFromTrustedIssuer`](#fetchcredentialsfromtrustedissuer) instead, which supports the different authorization methods (Redirect to Web / Presentation During Issuance).

##### Authorizations
The `authorizations` parameter is a list of `AuthorizationMethod` objects indicating the supported authorizations of the Wallet for the download flow. Currently, library supports two authorization flows - _Redirect To Web_ and _Presentation During Issuance_. Library exposes the supported authorization flows via class - `AuthorizationMethod`

1. Redirect To Web (for Authorization flow)

Redirect the user to the authorization endpoint (authorization server) in a web view or browser, and get the authorization response parameters back after successful authorization.

**Parameters :**

| Name        | Type                | Required | Default Value | Description                                                                                                                                                                         |
|-------------|---------------------|----------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| openWebPage | OpenWebPageCallback | Yes      | N/A           | Callback function to open the authorization endpoint in a web view or browser, and return the authorization response parameters (e.g., code, state) after successful authorization. |

**Example usage**
```kotlin
AuthorizationMethod.RedirectToWeb(
  openWebPage = object : OpenWebPageCallback {
    override suspend fun invoke(authorizationEndpoint: String): Map<String, Any> {
        // Handle the user authorization logic here
        // Open a web view or browser with the authorizationEndpoint
        // Return the authorization response parameters (e.g., code, state)
        val result: Map<String, Any> = openWebViewAndGetResult(authorizationEndpoint)
        return result
    }
  }
)
```
> Note: The Redirect to Web flow for an interactive authorization flow is exposed as an experimental API, and is expected to be improved in future releases.

2. Presentation During Issuance

Presentation During Issuance flow allows the Wallet to present a verifiable presentation to the Credential Issuer during the credential download process, which can be used by the issuer to verify certain claims about the user before issuing the credential. The authorization for the download here is presentation of another credential (or a verifiable presentation) instead of user interaction-based authorization as in Redirect To Web flow.

###### Specification Reference

This implementation follows - [OpenID4VCI v1.1 Specification Commit](https://github.com/openid/OpenID4VCI/blob/31636e9bb7f0eef6933175e1e41c78ce79a69783/1.1/openid-4-verifiable-credential-issuance-1_1.md)

> Note:
> - While this library primarily implements OpenID4VCI 1.0 and draft 13, the Presentation During Issuance feature follows the v1.1 specification as mentioned above.
> - For Presentation During Issuance flow, this VCI client library internally uses [inji-openid4vp](https://github.com/inji/inji-openid4vp/tree/master/kotlin) library to construct the VP and handle the presentation exchange with the issuer.

**Parameters :**

| Name                             | Type                                     | Required | Default Value    | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|----------------------------------|------------------------------------------|----------|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| selectCredentialsForPresentation | SelectCredentialsForPresentationCallback | Yes      | N/A              | Callback function to select credentials from the wallet to be presented to the issuer during issuance as per the Issuer's request. The callback will be invoked with a VP request (`AuthorizationRequest`); the Wallet uses this to ask the user to select credentials and then returns the selected credentials as a `Map<String, List<Credential>>`                                                  |
| signVerifiablePresentation       | SignVerifiablePresentationCallback       | Yes      | N/A              | Callback function to sign the data used for Verifiable Presentation construction. The callback will be invoked with a list of `UnsignedVPToken` to be signed, and the wallet needs to sign each with the appropriate key and return a list of `VPTokenSigningResult`.                                                                                                                                  |
| openid4vpWalletConfig            | WalletConfig                             | No       | `WalletConfig()` | Configuration passed to the underlying [inji-openid4vp](https://github.com/inji/inji-openid4vp/tree/master/kotlin) library (e.g. supported algorithms / formats). Defaults to the library's default `WalletConfig`.                                                                                                                                                                                  |


**Example usage**

```kotlin
AuthorizationMethod.PresentationDuringIssuance(
                            selectCredentialsForPresentation = object : SelectCredentialsForPresentationCallback {
                                    override suspend fun invoke(
                                        ovpRequest: AuthorizationRequest
                                    ): Map<String, List<Credential>> {
                                        // Handle the logic to select credentials from the wallet as per the presentation request
                                        // Handle the logic for obtaining consent from the user for presenting the credentials to the issuer
                                        val selectedCredentials: Map<String, List<Credential>> = selectCredentials(ovpRequest)
                                        return selectedCredentials
                                    }
                                },
                            signVerifiablePresentation = object : SignVerifiablePresentationCallback {
                                    override suspend fun invoke(
                                        payload: List<UnsignedVPToken>
                                    ): List<VPTokenSigningResult> {
                                        // Handle the logic to sign the data with the appropriate key as per the credential descriptor and signature suite
                                        // From each UnsignedVPToken, identify the key and algorithm to be used for signing, sign the data, and return the signature result to the library
                                        val signedData : List<VPTokenSigningResult> = signDataForVP(payload)
                                        // since the payload is a list of data to be signed for each credential, the result is also a list containing the signature result for each credential, and the library will take care of constructing the VP with the respective proof for each credential accordingly
                                        // To avoid any confusion, the library will expect the implementation of this callback to return a list of signature results corresponding to each credential in the same order as the payload, and the library will match the signature result with the respective credential based on the order of the payload list.
                                        return  signedData
                                    }
                            }
                    )
```

[//]: # (The branch in inji-wallet for pdi docs link is pointed to master intentionally to ensure that the latest documentation is always referred.)
> For more details on the Presentation During Issuance flow and the expected implementation of the callbacks, please refer to the [inji-wallet Presentation During Issuance documentation](https://github.com/inji/inji-wallet/blob/master/docs/presentation-during-issuance-support.md)


### 3.3 requestCredential (removed in 1.0)

> ⚠️ **Removed in 1.0**: The low-level `requestCredential` method (deprecated since `0.4.0`) and its `IssuerMetaData` DTO have been removed. Please migrate to [`fetchCredentialsUsingCredentialOffer()`](#fetchcredentialsusingcredentialoffer) or [`fetchCredentialsFromTrustedIssuer()`](#fetchcredentialsfromtrustedissuer), which fetch the issuer metadata, build the credential request (for OID4VCI 1.0 or draft 13), and download the credential for you.

---

## 🚨 Removed APIs

The following methods (and the `IssuerMetaData` DTO they relied on) were deprecated in earlier releases and have been **removed in 1.0**. Please migrate to the suggested alternatives.

| Method Name                        | Deprecated Since | Removed In | Suggested Alternative                                                                                                                                      |
|------------------------------------|------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| requestCredentialFromTrustedIssuer | 0.7.0            | 1.0.0      | [fetchCredentialsFromTrustedIssuer](#fetchcredentialsfromtrustedissuer)                                                                                    |
| requestCredentialByCredentialOffer | 0.7.0            | 1.0.0      | [fetchCredentialsUsingCredentialOffer](#fetchcredentialsusingcredentialoffer)                                                                              |
| requestCredential                  | 0.4.0            | 1.0.0      | [fetchCredentialsUsingCredentialOffer()](#fetchcredentialsusingcredentialoffer) or [fetchCredentialsFromTrustedIssuer()](#fetchcredentialsfromtrustedissuer) |

---

## 🔐 Security Support

-  **PKCE (Proof Key for Code Exchange)** handled internally (RFC 7636)
-  Supports `S256` code challenge method
-  Secure `nonce` binding via proof JWTs

---

## 🛑 Error Handling

All exceptions thrown by the library are subclasses of `VCIClientException`.  
They carry structured fields that help consumers identify whether the failure came from the library itself, a wrapped library exception, or an upstream server response.

### `VCIClientException` fields

| Field                     | Type      | Meaning |
|---------------------------|-----------|---------|
| `code`                    | `String`  | The library-defined `VCI-*` error code. When the exception wraps another `VCIClientException`, `code` carries the **root** code resolved from the cause chain; otherwise it is the exception's own code. |
| `message`                 | `String`  | Human-readable summary of the failure, ready for logging or diagnostics. |
| `issuerErrorCode`         | `String?` | The issuer or authorization server `error` value when the remote service returned a structured OAuth/OID4VCI style error response. |
| `issuerErrorDescription`  | `String?` | The upstream `error_description` value when available. If the response body is not parseable JSON, the raw response body may be propagated here for diagnostics. |

### Structured error handling

> New in `1.0.0`: if you are upgrading from `0.7.0`, where only `code` and `message` were reliably available, the structured fields below are new.

The error model exposes the following fields so consumers can react precisely to failures:

- `code` identifies the root library failure. When an exception wraps another library exception, `code` resolves to the deepest `VCI-*` code in the cause chain rather than the wrapper's own code.
- `issuerErrorCode` captures the upstream server `error` field when present.
- `issuerErrorDescription` captures the upstream `error_description`, or the raw error body when structured parsing is not possible.

This means consumers can distinguish between:

- the original underlying library failure (surfaced through `code` even across wrapping),
- and a server-originated error payload returned by the issuer or authorization server.

#### Recommendations for consumers

- If your integration only switches on `code`, it will continue to work — and `code` now reflects the root failure category even when the exception is wrapped at the API boundary.
- If you want to infer server-side failures, use `issuerErrorCode` and `issuerErrorDescription` rather than parsing `message`.
- If you want better observability, log all three fields: `code`, `issuerErrorCode`, and `issuerErrorDescription`.
- If you want better retry and UX decisions, use `code` for the top-level category and `issuerErrorCode` for server-specific remediation.

### What each field means for consumers

- Use `code` for primary client-side branching, telemetry dimensions, and product analytics. It identifies the root library failure even when the exception is wrapped.
- Use `issuerErrorCode` to decide whether a failure is recoverable through user action, such as re-authentication, retry, or correcting a request.
- Use `issuerErrorDescription` for logs, support tooling, and developer diagnostics. Avoid showing it directly to end users without sanitization because it may contain server-specific text.

Some public API methods may wrap an internal `VCIClientException` into another `VCIClientException` before rethrowing it. This improves consistency at the API boundary without losing the root cause.

Example:

- `getIssuerMetadata()` may wrap the failure at the API boundary, but `code` still resolves to `VCI-009` when the underlying failure was an issuer metadata fetch error.
- `issuerErrorCode` may contain a remote value such as `invalid_token` if the upstream endpoint returned it.

### Recommended consumer handling

```kotlin
try {
    val credentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(
        credentialOffer = credentialOffer,
        clientMetadata = clientMetadata,
        getTxCode = getTxCode,
        authorizations = authorizations,
        getTokenResponse = getTokenResponse,
        getProofs = getProofs
    )
} catch (e: VCIClientException) {
    logger.error(
        "VCI request failed. code=${e.code}, " +
            "issuerCode=${e.issuerErrorCode}, issuerDescription=${e.issuerErrorDescription}, " +
            "message=${e.message}"
    )

    when (e.code) {
        "VCI-007" -> showRetryMessage()
        "VCI-003" -> triggerTokenRefresh()
        "VCI-011" -> showAuthorizationFailure()
        else -> showGenericFailure()
    }
}
```

### Error code reference

| Code    | Exception Type                          | Description                                                                                              |
|---------|-----------------------------------------|----------------------------------------------------------------------------------------------------------|
| VCI-001 | `AuthorizationServerDiscoveryException` | Failed to discover authorization server                                                                  |
| VCI-002 | `DownloadFailedException`               | Failed to download credential                                                                            |
| VCI-003 | `InvalidAccessTokenException`           | Access token is invalid                                                                                  |
| VCI-004 | `InvalidDataProvidedException`          | Required details not provided                                                                            |
| VCI-005 | `InvalidPublicKeyException`             | Invalid public key passed                                                                                |
| VCI-006 | `NetworkRequestFailedException`         | Network request failed                                                                                   |
| VCI-007 | `NetworkRequestTimeoutException`        | Network request timed-out                                                                                |
| VCI-008 | `CredentialOfferFetchFailedException`   | Failed to fetch credential offer                                                                         |
| VCI-009 | `IssuerMetadataFetchException`          | Failed to fetch issuerMetadata                                                                           |
| VCI-010 | `VCIClientException`                    | Generic API-boundary wrapper or unknown exception surfaced by `VCIClient` public methods                |
| VCI-011 | `InteractiveAuthorizationException`     | Failed to perform Interactive authorization (Presentation During Issuance / Redirect to Web interaction) |


---

## 🧪 Testing

Mock-based tests are available covering:

- Credential download flow (offer + trusted issuer)
- Proof JWT signing callbacks
- Token exchange logic

> See `VCIClientTest` for full coverage

## Platform Support

- **Kotlin:** 1.9+
- **JVM:** Java 17
- **Android:** minSdk 23, compileSdk 34
- **Gradle:** 8.0+
- **AGP (Android Gradle Plugin):** 8.0+

## Documentation

- Architecture decisions are documented in the [INJI VCI Client ADR directory](../doc/adr).
- Documentation of the features are available in the [INJI VCI Client docs directory](../doc).

**Note: The iOS (Swift) library is available in the [INJI VCI Client iOS repository](https://github.com/inji/inji-vci-client-ios-swift).**

---

## Example App

A complete sample app demonstrating credential issuance flows, proof JWT signing, and error handling with `VCIClient` is available here:

[Example Android App](./example)

- Shows both **Credential Offer** and **Trusted Issuer** flows
- Includes best practices for callbacks and UI integration

> Use the example app to quickly get started and see the library in action.

---
</content>
</invoke>
