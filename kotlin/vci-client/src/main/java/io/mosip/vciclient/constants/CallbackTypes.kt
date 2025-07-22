package io.mosip.vciclient.constants

import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

typealias TxCodeCallback = (suspend (inputMode: String?, description: String?, length: Int?) -> String)
typealias AuthorizeUserCallback = (suspend (authorizationUrl: String) -> String)
typealias TokenResponseCallback = suspend (tokenRequest: TokenRequest) -> TokenResponse
typealias ProofJwtCallback = (suspend (
    credentialIssuer: String,
    cNonce: String?,
    proofSigningAlgorithmsSupported: List<String>
) -> String)

typealias CheckIssuerTrustCallback = (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)