# Migration Guide: inji-vci-client 0.7.0 → 1.0.0

This guide helps Kotlin developers upgrade from **`inji-vci-client` 0.7.0** to **1.0.0**.

Scope: **breaking changes in the public API** — `VCIClient` class, its credential download methods, and the Presentation During Issuance (PDI) authorization callbacks.

Note:
- The core flow and concepts remain the same, but method names, the proof callback, the credential response model, and the PDI callback signatures have changed to align with the final OpenID4VCI 1.0 specification.

---

## Quick flow overview

1. `VCIClient(traceabilityId)` initialises the client for the session.
2. `getIssuerMetadata(credentialIssuer =)` fetches issuer well-known metadata.
3. `getCredentialConfigurationsSupported(credentialIssuer =)` fetches supported credential configurations.
4. `fetchCredentialsUsingCredentialOffer(...)` (issuer-initiated) or `fetchCredentialsFromTrustedIssuer(...)` (wallet-initiated) downloads credentials and returns a `CredentialResponse`.
5. Your wallet reads `credentialResponse.credentials` — a `List<CredentialItem>` list — and renders each item.

---

## Feature overview

1. **0.7.0**
   1. Supported OID4VCI draft 13.
   2. Credential download methods returned a single `credential: AnyCodable`.
   3. Proof callback accepted one nonce and returned a single JWT string.

2. **1.0.0**
   1. Supports OID4VCI **1.0** with retained draft 13 backward compatibility — the library auto-detects the issuer's spec version from its metadata.
   2. Credential download methods return a `credentials: List<CredentialItem>` list, matching the OID4VCI 1.0 response shape.
   3. Proof callback returns a `CredentialRequestProofs` object, supporting one or more proofs per request.
   4. **PDI `selectCredentialsForPresentation` callback** now returns `Map<String, List<Credential>>` instead of `Map<String, Map<FormatType, Any>>`.
   5. **PDI `signVerifiablePresentation` callback** now returns `List<VPTokenSigningResult>` instead of `List<VPTokenSigningResultV2>`.
   7. **PDI response modes updated**: `iar_post` / `iar_post.jwt` are the supported response modes.
   8. Issuer metadata fetch now validates that `credential_issuer` in the well-known response matches the requested issuer [OID4VCI §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.1).
   9. `VCIClientException` carries structured upstream error fields (`issuerErrorCode`, `issuerErrorDescription`).
   10. Legacy low-level APIs (`requestCredential`, `requestCredentialByCredentialOffer`, `requestCredentialFromTrustedIssuer`) have been removed.

---

## TL;DR (what you must change)

1. **Rename credential offer method**
   - **0.7.0**: `fetchCredentialUsingCredentialOffer(...)`
   - **1.0.0**: `fetchCredentialsUsingCredentialOffer(...)` (plural *Credentials*)

2. **Rename trusted issuer method**
   - **0.7.0**: `fetchCredentialFromTrustedIssuer(...)`
   - **1.0.0**: `fetchCredentialsFromTrustedIssuer(...)` (plural *Credentials*)

3. **Replace `getProofJwt` callback with `getProofs`**
   - **0.7.0**: `getProofJwt = (credentialIssuer, cNonce, proofSigningAlgorithmsSupported) -> String`
   - **1.0.0**: `getProofs = (credentialIssuer, nonce, proofSigningAlgorithmsSupported) -> CredentialRequestProofs`

4. **Update credential response access**
   - **0.7.0**: `credentialResponse?.credential` (`AnyCodable`)
   - **1.0.0**: `credentialResponse.credentials` (`List<CredentialItem>`); access each via `item.credential`

5. **Update PDI callbacks** — `selectCredentialsForPresentation` now returns `Map<String, List<Credential>>` (not `Map<String, Map<FormatType, Any>>`); `signVerifiablePresentation` now returns `List<VPTokenSigningResult>` (not `List<VPTokenSigningResultV2>`).


7. **Update PDI response mode handling** — use `iar_post` / `iar_post.jwt` response modes.

8. **Remove any calls to deleted APIs** — `requestCredential`, `requestCredentialByCredentialOffer`, and `requestCredentialFromTrustedIssuer` are gone; migrate to the `fetchCredentials*` methods.

9. **Update error handling** — `VCIClientException` now exposes `issuerErrorCode` and `issuerErrorDescription` alongside `code` and `message`.

---

## Before vs After: credential offer download

### 0.7.0 (old)

```kotlin
val credentialResponse: CredentialResponse? = vciClient.fetchCredentialUsingCredentialOffer(
    credentialOffer = "openid-credential-offer://?credential_offer_uri=...",
    clientMetadata = ClientMetadata(clientId = "sample-client-id", redirectUri = "https://sample-wallet.com/callback"),
    getTxCode = { inputMode, description, length -> "sampleTxCode"
    },
    authorizationMethods = listOf(
        AuthorizationMethod.presentationDuringIssuance(
            selectCredentialsForPresentation = { vpRequest -> try selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation = { unsignedVPTokens -> try signVerifiablePresentationCallback(unsignedVPTokens = unsignedVPTokens)
            },
            ldpVpSignatureSuite = "Ed25519Signature2020"
        ),
        AuthorizationMethod.redirectToWeb(openWebPage = openWebPageCallback())
    ),
    getTokenResponse = { tokenRequest -> TokenResponse(accessToken = "sampleAccessToken", cNonce = "sampleNonce",
                      tokenType = "Bearer", expiresIn = 3600, cNonceExpiresIn = 3600)
    },
    getProofJwt = { credentialIssuer, cNonce, proofSigningAlgorithmsSupported -> // Sign JWT and return the compact serialization
        "sampleProofJwt"
    },
    onCheckIssuerTrust = { credentialIssuer, issuerDisplay -> true },
    downloadTimeoutInMillis = 10_000
)

credentialResponse?.credential           // AnyCodable — the single downloaded credential
credentialResponse?.credentialConfigurationId
credentialResponse?.credentialIssuer
```

### 1.0.0 (new)

```kotlin
val credentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(
    credentialOffer = "openid-credential-offer://?credential_offer_uri=...",
    clientMetadata = ClientMetadata(clientId = "sample-client-id", redirectUri = "https://sample-wallet.com/callback"),
    getTxCode = { inputMode, description, length -> "sampleTxCode"
    },
    authorizationMethods = listOf(
        AuthorizationMethod.presentationDuringIssuance(
            selectCredentialsForPresentation = { vpRequest -> try selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation = { unsignedVPTokens -> try signVerifiablePresentationCallback(unsignedVPTokens = unsignedVPTokens)
            }
        ),
        AuthorizationMethod.redirectToWeb(openWebPage = openWebPageCallback())
    ),
    getTokenResponse = { tokenRequest -> TokenResponse(accessToken = "sampleAccessToken", cNonce = "sampleNonce",
                      tokenType = "Bearer", expiresIn = 3600, cNonceExpiresIn = 3600)
    },
    getProofs = { credentialIssuer, nonce, proofSigningAlgorithmsSupported -> // Sign JWT(s) and wrap in CredentialRequestProofs
        CredentialRequestProofs(proofs = listOf("sampleProofJwt"))
    },
    onCheckIssuerTrust = { credentialIssuer, issuerDisplay -> true },
    downloadTimeoutInMillis = 10_000
)

credentialResponse.credentials            // List<CredentialItem> — list of downloaded credentials
credentialResponse.credentials.firstOrNull()?.credential  // AnyCodable of the first credential
credentialResponse.credentialConfigurationId
credentialResponse.credentialIssuer
```

### Parameter mapping

| 0.7.0 parameter                                                                                                                               | 1.0.0 parameter             | Migration note                                                                |
|-----------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|-------------------------------------------------------------------------------|
| `getProofJwt = ProofJwtCallback`                                                                                                               | `getProofs = ProofsCallback` | Return a `CredentialRequestProofs(proofs = listOf(...])` instead of a plain `String` |
| `credentialOffer`, `clientMetadata`, `getTxCode`, `authorizationMethods`, `getTokenResponse`, `onCheckIssuerTrust`, `downloadTimeoutInMillis` | _(unchanged)_               | Same parameter names and types                                                |

### Response mapping

| 0.7.0 field                          | 1.0.0 field                         | Migration note                                                                |
|--------------------------------------|-------------------------------------|-------------------------------------------------------------------------------|
| `credential: AnyCodable`             | `credentials: List<CredentialItem>`     | Iterate `credentials`; each `CredentialItem` exposes `credential: AnyCodable` |
| `credentialConfigurationId = String?` | `credentialConfigurationId = String` | No longer optional                                                            |
| `credentialIssuer = String?`          | `credentialIssuer = String`          | No longer optional                                                            |

---

## Before vs After: trusted issuer download

### 0.7.0 (old)

```kotlin
val credentialResponse: CredentialResponse? = vciClient.fetchCredentialFromTrustedIssuer(
    credentialIssuer = "https://sample-issuer.com",
    credentialConfigurationId = "DriversLicense",
    clientMetadata = ClientMetadata(clientId = "sample-client-id", redirectUri = "https://sample-wallet.com/callback"),
    authorizationMethods = listOf(
        AuthorizationMethod.presentationDuringIssuance(
            selectCredentialsForPresentation = { vpRequest -> try selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation = { unsignedVPTokens -> try signVerifiablePresentationCallback(unsignedVPTokens = unsignedVPTokens)
            },
            ldpVpSignatureSuite = "Ed25519Signature2020"
        ),
        AuthorizationMethod.redirectToWeb(openWebPage = openWebPageCallback())
    ),
    getTokenResponse = { tokenRequest -> TokenResponse(accessToken = "sampleAccessToken", cNonce = "sampleNonce",
                      tokenType = "Bearer", expiresIn = 3600, cNonceExpiresIn = 3600)
    },
    getProofJwt = { credentialIssuer, cNonce, proofSigningAlgorithmsSupported -> "sampleProofJwt"
    },
    downloadTimeoutInMillis = 10_000
)

credentialResponse?.credential
credentialResponse?.credentialConfigurationId
credentialResponse?.credentialIssuer
```

### 1.0.0 (new)

```kotlin
val credentialResponse = vciClient.fetchCredentialsFromTrustedIssuer(
    credentialIssuer = "https://sample-issuer.com",
    credentialConfigurationId = "DriversLicense",
    clientMetadata = ClientMetadata(clientId = "sample-client-id", redirectUri = "https://sample-wallet.com/callback"),
    authorizationMethods = listOf(
        AuthorizationMethod.presentationDuringIssuance(
            selectCredentialsForPresentation = { vpRequest -> try selectCredentialsForPresentationCallback(vpRequest: vpRequest)
            },
            signVerifiablePresentation = { unsignedVPTokens -> try signVerifiablePresentationCallback(unsignedVPTokens = unsignedVPTokens)
            }
        ),
        AuthorizationMethod.redirectToWeb(openWebPage = openWebPageCallback())
    ),
    getTokenResponse = { tokenRequest -> TokenResponse(accessToken = "sampleAccessToken", cNonce = "sampleNonce",
                      tokenType = "Bearer", expiresIn = 3600, cNonceExpiresIn = 3600)
    },
    getProofs = { credentialIssuer, nonce, proofSigningAlgorithmsSupported -> CredentialRequestProofs(proofs = listOf("sampleProofJwt"))
    },
    downloadTimeoutInMillis = 10_000
)

credentialResponse.credentials
credentialResponse.credentialConfigurationId
credentialResponse.credentialIssuer
```

The parameter and response mapping is the same as described in the credential offer section above.

---

## Before vs After: Presentation During Issuance (PDI) callbacks

### What stays the same

- `AuthorizationMethod.presentationDuringIssuance(...)` is still the way to pass PDI into both download methods.
- `selectCredentialsForPresentation` and `signVerifiablePresentation` callbacks are still required.

### What changes in practice

1. **`selectCredentialsForPresentation` return type changed**
   - **0.7.0**: returned `Map<String, Map<FormatType, Any>>`
   - **1.0.0**: returns `Map<String, List<Credential>>` — a flat list of `Credential` objects per input descriptor ID /Credential query ID

2. **`signVerifiablePresentation` callback inputs and return changed**
   - **0.7.0**: Input: `List<UnsignedVPTokenV2>`
   - **1.0.0**: Input: `List<UnsignedVPToken>` (adds the `id` property in addition to `format`, `holderKeyReference`, `signatureAlgorithm`, and `dataToSign`)

   - **0.7.0**: Returns: `List<VPTokenSigningResultV2>`
   - **1.0.0**: Returns: `List<VPTokenSigningResult>` (adds the `id` property in addition to `signedData`)

3. **Two new PDI parameters added**
   - `openid4vpWalletConfig` — optional OpenID4VP wallet configuration (trusted verifiers, supported formats, etc.)

4. **Response modes updated**
   - `iar_post` and `iar_post.jwt` are the supported response modes in 1.0.0

### 0.7.0 PDI usage (old)

```kotlin
AuthorizationMethod.presentationDuringIssuance(
    selectCredentialsForPresentation = { presentationRequest -> // 0.7.0: returned Map<String, Map<FormatType, Any>>
        val selectedCredentials: Map<String, Map<FormatType, Any>> = selectCredentials(presentationRequest)
        return selectedCredentials
    },
    signVerifiablePresentation = { payload -> // 0.7.0: payload items are List<UnsignedVPTokenV2>; return List<VPTokenSigningResultV2>
        val signedData: List<VPTokenSigningResultV2> = signDataForVP(payload)
        return signedData
    },
    ldpVpSignatureSuite = "Ed25519Signature2020"
)
```

### 1.0.0 PDI usage (new)

```kotlin
AuthorizationMethod.presentationDuringIssuance(
        // Required only for ldp_vc — canonicalize JSON-LD and return base64url-encoded hash
        return canonicalizeAndHash(data)
    },
    openid4vpWalletConfig = WalletConfig(), // Optional — use defaults or pass your config
    selectCredentialsForPresentation = { presentationRequest -> // 1.0.0: return Map<String, List<Credential>> — flat list per descriptor/query ID
        val selectedCredentials: Map<String, List<Credential>> = selectCredentials(presentationRequest)
        return selectedCredentials
    },
    signVerifiablePresentation = { payload -> // 1.0.0: payload items are List<UnsignedVPToken>; return List<VPTokenSigningResult>
        val signedData: List<VPTokenSigningResult> = signDataForVP(payload)
        return signedData
    }
)
```

### Parameter mapping

| 0.7.0 parameter                    | 1.0.0 parameter                    | Change                                                                          |
|------------------------------------|------------------------------------|---------------------------------------------------------------------------------|
| _(not present)_                    | `openid4vpWalletConfig`            | **New** — optional OpenID4VP wallet config                                      |
| `selectCredentialsForPresentation` | `selectCredentialsForPresentation` | Return type changed: `Map<String, Map<FormatType, Any>>` → `Map<String, List<Credential>>` |
| `signVerifiablePresentation`       | `signVerifiablePresentation`       | Return type changed: `List<VPTokenSigningResultV2>` → `List<VPTokenSigningResult>`      |
| `ldpVpSignatureSuite`              | (not present)                      | Removed                                                                         |

---

## Before vs After: error handling

### What stays the same

- All exceptions are subclasses of `VCIClientException`.
- `code` (`VCI-*`) and `message` continue to work as before.

### New in 1.0.0

Two structured fields are now available on `VCIClientException`:

| New field                | Type      | Meaning                                                                                                        |
|--------------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| `issuerErrorCode`        | `String?` | The `error` value returned by the issuer or authorization server in a structured OAuth/OID4VCI error response. |
| `issuerErrorDescription` | `String?` | The `error_description` from the upstream server, or the raw body when structured parsing is not possible.     |

Additionally, `code` now resolves to the **root** error code across the cause chain — if an exception wraps another `VCIClientException`, `code` carries the deepest `VCI-*` code rather than the wrapper's own code.

### 0.7.0 error handling (old)

```kotlin
try {
    val credentialResponse = vciClient.fetchCredentialUsingCredentialOffer(...)
} catch (error: VCIClientException) {
    when (error.code) {
        "VCI-007" -> showRetryMessage()
        else -> showGenericFailure(error.message)
    }
}
```

### 1.0.0 error handling (new)

```kotlin
try {
    val credentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(...)
} catch (error: VCIClientException) {
    logger.error(
        "VCI request failed. code=${error.code}, " +
        "issuerCode=${error.issuerErrorCode ?: "nil"}, " +
        "issuerDescription=${if (error.issuerErrorDescription != null) "<redacted>" else "nil"}, " +
        "message=${error.message}"
    )

    when (error.code) {
    "VCI-007" -> showRetryMessage()
    "VCI-003" -> triggerTokenRefresh()
    "VCI-011" -> showAuthorizationFailure()
    else -> showGenericFailure()
    }
}
```

---

## Removed and changed APIs

> **Notice**
>
> 1.0.0 retains the core `VCIClient` entry point but removes the legacy low-level methods deprecated since 0.7.0, and renames the two primary download methods.

### API changes

| 0.7.0                                                                    | 1.0.0 status      | Change                                                                                                                                        |
|--------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `fetchCredentialUsingCredentialOffer(...)`                               | **Renamed**       | Use `fetchCredentialsUsingCredentialOffer(...)`                                                                                               |
| `fetchCredentialFromTrustedIssuer(...)`                                  | **Renamed**       | Use `fetchCredentialsFromTrustedIssuer(...)`                                                                                                  |
| `getProofJwt` callback                                                   | **Replaced**      | Use `getProofs` returning `CredentialRequestProofs`                                                                                           |
| `CredentialResponse.credential: AnyCodable`                              | **Replaced**      | Use `CredentialResponse.credentials: List<CredentialItem>`                                                                                        |
| PDI `selectCredentialsForPresentation` → `Map<String, Map<FormatType, Any>>` | **Changed**       | Now returns `Map<String, List<Credential>>`                                                                                                          |
| PDI `signVerifiablePresentation`                                         | **Changed**       | Input changed from `UnsignedVPTokenV2` to `UnsignedVPToken`. Return type changed from `List<VPTokenSigningResultV2>` to `List<VPTokenSigningResult>`. |
| PDI _(no `openid4vpWalletConfig`)_                                       | **New parameter** | Optional OpenID4VP wallet configuration                                                                                                       |

### APIs removed in 1.0.0

| Removed method                            | Deprecated since | Replacement                                                                             |
|-------------------------------------------|------------------|-----------------------------------------------------------------------------------------|
| `requestCredentialByCredentialOffer(...)` | 0.7.0            | `fetchCredentialsUsingCredentialOffer(...)`                                             |
| `requestCredentialFromTrustedIssuer(...)` | 0.7.0            | `fetchCredentialsFromTrustedIssuer(...)`                                                |
| `requestCredential(...)`                  | 0.7.0            | `fetchCredentialsUsingCredentialOffer(...)` or `fetchCredentialsFromTrustedIssuer(...)` |

### Unchanged APIs

The following public methods are unchanged in 1.0.0:

- `VCIClient(traceabilityId)`
- `getIssuerMetadata(credentialIssuer =)`
- `getCredentialConfigurationsSupported(credentialIssuer =)`

---

## Minimal working Kotlin example in 1.0.0

```kotlin
import io.mosip.vciclient.VCIClient

fun downloadCredential(
    traceabilityId: String,
    credentialOffer: String,
    clientId: String,
    redirectUri: String
): List<CredentialItem> {

    val vciClient = VCIClient(traceabilityId = traceabilityId)

    val credentialResponse = vciClient.fetchCredentialsUsingCredentialOffer(
        credentialOffer = credentialOffer,
        clientMetadata = ClientMetadata(clientId = clientId, redirectUri = redirectUri),
        getTxCode = { inputMode, description, length -> // Prompt user for transaction code if required
            return "userProvidedTxCode"
        },
        authorizationMethods = listOf(
        AuthorizationMethod.presentationDuringIssuance(
                selectCredentialsForPresentation = { presentationRequest -> // Return wallet credentials matching the presentation request
                    emptyMap()
                },
                signVerifiablePresentation = { payload -> // Sign VP payload; return List<VPTokenSigningResult>
                    emptyList()
                }
            ),
        AuthorizationMethod.redirectToWeb(openWebPage = { authorizationEndpoint -> // Open web view, complete authorization, return response params
                emptyMap()
            })
        ),
        getTokenResponse = { tokenRequest -> // Exchange authorization grant for access token
            return TokenResponse(
                accessToken = "accessToken",
                cNonce = "nonce",
                tokenType = "Bearer",
                expiresIn = 3600,
                cNonceExpiresIn = 3600
            )
        },
        getProofs = { credentialIssuer, nonce, proofSigningAlgorithmsSupported -> // Build and sign proof JWT(s) using nonce and supported algorithms
            val signedProofJwt = buildAndSignProofJwt(nonce = nonce, issuer = credentialIssuer)
            return CredentialRequestProofs(proofs = listOf(signedProofJwt))
        },
        onCheckIssuerTrust = { credentialIssuer, issuerDisplay -> // Return true if the issuer is trusted by the wallet
            return true
        },
        downloadTimeoutInMillis = 10_000
    )

    // credentialResponse.credentials is List<CredentialItem>
    return credentialResponse.credentials
}

// Helpers (implement in your wallet app)

fun buildAndSignProofJwt(nonce: String, issuer: String): String {
    // Build the proof JWT header/payload, sign with your holder key, and return the compact serialization
    return "eyJ..."
}
```

Notes:
- Replace stub callback bodies with your wallet's actual implementation.
- `getProofs` replaces the old `getProofJwt` — wrap your signed JWT in `CredentialRequestProofs(proofs = listOf(...])`.
- Iterate `credentialResponse.credentials` to access each downloaded credential via `.credential` (`AnyCodable`).

---

## Appendix: Key Kotlin types and entry points

| Purpose                              | Type / File                                                             |
|--------------------------------------|-------------------------------------------------------------------------|
| Entry point                          | `VCIClient`                                                             |
| Credential download (offer)          | `fetchCredentialsUsingCredentialOffer(...)`                             |
| Credential download (trusted issuer) | `fetchCredentialsFromTrustedIssuer(...)`                                |
| Proof callback return type           | `CredentialRequestProofs`                                               |
| Credential response                  | `CredentialResponse`                                                    |
| Individual credential in response    | `CredentialItem`                                                        |
| Client registration details          | `ClientMetadata`                                                        |
| Token exchange response              | `TokenResponse`                                                         |
| Authorization flows                  | `AuthorizationMethod` (`.redirectToWeb`, `.presentationDuringIssuance`) |
| Exception base type                  | `VCIClientException`                                                    |
