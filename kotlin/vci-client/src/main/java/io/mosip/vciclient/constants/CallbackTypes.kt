package io.mosip.vciclient.constants

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenV2
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResultV2
import io.mosip.openID4VP.constants.FormatType
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

typealias TxCodeCallback = (suspend (inputMode: String?, description: String?, length: Int?) -> String)
typealias AuthorizeUserCallback = (suspend (authorizationUrl: String) -> String)
typealias TokenResponseCallback = suspend (tokenRequest: TokenRequest) -> TokenResponse
internal typealias ProofJwtCallback = (suspend (
    credentialIssuer: String,
    cNonce: String?,
    proofSigningAlgorithmsSupported: List<String>
) -> String)
typealias ProofsCallback = (suspend (
    credentialIssuer: String,
    nonce: String?,
    proofSigningAlgorithmsSupported: List<String>
) -> CredentialRequestProofs)

typealias CheckIssuerTrustCallback = (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)
typealias SelectCredentialsForPresentationCallback = (suspend (ovpRequest: AuthorizationRequest) -> Map<String, Map<FormatType, List<Any>>>)
typealias SignVerifiablePresentationCallback = suspend (
    payload: List<UnsignedVPTokenV2>,
) -> List<VPTokenSigningResultV2>
typealias OpenWebPageCallback = (suspend (authorizationUrl: String) -> Map<String, Any>)
