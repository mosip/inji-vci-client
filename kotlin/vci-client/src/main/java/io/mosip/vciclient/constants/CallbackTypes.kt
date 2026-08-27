package io.mosip.vciclient.constants

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.wallet.Credential
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.proof.CredentialRequestProofMetadata
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

typealias TxCodeCallback = (suspend (inputMode: String?, description: String?, length: Int?) -> String)
typealias AuthorizeUserCallback = (suspend (authorizationUrl: String) -> String)
typealias TokenResponseCallback = suspend (tokenRequest: TokenRequest) -> TokenResponse
internal typealias ProofJwtCallback = (suspend (credentialRequestProofMetadata: CredentialRequestProofMetadata) -> String)
typealias ProofsCallback = (suspend (credentialRequestProofMetadata: CredentialRequestProofMetadata) -> CredentialRequestProofs)

typealias CheckIssuerTrustCallback = (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)
typealias SelectCredentialsForPresentationCallback = (suspend (ovpRequest: AuthorizationRequest) -> Map<String, List<Credential>>)
typealias SignVerifiablePresentationCallback = suspend (
    payload: List<UnsignedVPToken>,
) -> List<VPTokenSigningResult>
typealias OpenWebPageCallback = (suspend (authorizationUrl: String) -> Map<String, Any>)
