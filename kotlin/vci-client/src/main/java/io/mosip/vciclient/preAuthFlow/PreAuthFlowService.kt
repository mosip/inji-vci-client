package io.mosip.vciclient.preAuthFlow

import io.mosip.vciclient.authorizationServer.AuthServerResolver
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialRequest.CredentialRequestExecutor
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenService


class PreAuthFlowService {
    suspend fun requestCredentials(
        issuerMetadataResult: IssuerMetadataResult,
        offer: CredentialOffer,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        getProofJwt: suspend (accessToken: String, cNonce: String?, issuerMetadata: Map<String, *>, credentialConfigurationId: String) -> String,
        credentialConfigurationId: String,
        downloadTimeoutInMilliSeconds: Long? = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
    ): CredentialResponse? {
        val authServerMetadata =
            AuthServerResolver().resolveForPreAuth(issuerMetadataResult.issuerMetadata, offer)
        val tokenEndpoint = authServerMetadata.tokenEndpoint
        val txCode = if (offer.grants?.preAuthorizedGrant?.txCode !== null) {
            val txCode = offer.grants.preAuthorizedGrant.txCode
            getTxCode?.invoke(txCode.inputMode, txCode.description, txCode.length)
                ?: throw DownloadFailedException("tx_code required but no provider was given.")
        } else null
        val token = offer.grants?.preAuthorizedGrant?.let {
            TokenService().getAccessToken(
                tokenEndpoint = tokenEndpoint!!,
                preAuthCode = it.preAuthorizedCode, txCode = txCode
            )
        } ?: throw InvalidDataProvidedException("Token response missing")
        val proof = JWTProof(
            getProofJwt(
                token.accessToken,
                token.cNonce,
                issuerMetadataResult.raw,
                credentialConfigurationId
            )
        )
        return CredentialRequestExecutor(traceabilityId = traceabilityId).requestCredential(
            issuerMetadataResult.issuerMetadata,
            proof,
            token.accessToken,
            downloadTimeoutInMilliSeconds,
        )
    }
}
