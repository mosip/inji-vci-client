# INJI VCI Client

The **Inji VCI Client** is a library built to simplify credential issuance via [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) protocol.  
It supports **Issuer Initiated (Credential Offer)** and **Wallet Initiated (Trusted Issuer)** flows, with secure proof handling, PKCE support, and custom error handling.

---

## 📋 Specifications supported

The implementation follows
- OpenID for Verifiable Credential Issuance - 1.0
- OpenID for Verifiable Credential Issuance - draft 13

## ✨ Features

- Request credentials from OID4VCI-compliant credential issuers
- Supports both the Verifiable Credential download flows defined in the OID4VCI specification:
    - Issuer Initiated Flow (Credential Offer Flow).
    - Wallet Initiated Flow (Trusted Issuer Flow).
- Authorization server discovery for both download flows
- PKCE-compliant OAuth 2.0 Authorization Code flow (RFC 7636)
    - PKCE session is managed internally by the library
- Pushed Authorization Requests (PAR) support (RFC 9126)
    - Used automatically when the authorization server advertises a `pushed_authorization_request_endpoint`
    - Falls back to a standard authorization request if the push fails and PAR is not mandated by the authorization server
- Well-defined **exception handling** with `VCI-XXX` error codes (see more on [this](./kotlin/README.md#-error-handling))
- Support for multiple Credential formats:
    - `ldp_vc`
    - `mso_mdoc`
    - `vc+sd-jwt` / `dc+sd-jwt`
- Presentation During Issuance (PDI) support for both download flows (For more details on PDI support, please refer to the [Presentation During Issuance documentation](./doc/presentation-during-issuance-support.md))

> ⚠️ Consumer of this library is responsible for processing and rendering the credential after it is downloaded.




## 📚 Library implementations available in:
This library is officially supported and available in both Kotlin and Swift, ensuring seamless integration across Android and iOS platforms. The references for both implementations are provided below:

* [Kotlin](./kotlin)
* [Swift](https://github.com/inji/inji-vci-client-ios-swift)