package io.mosip.vciclient.preAuthCodeFlow

import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService

class PreAuthCodeFlowService {
    suspend fun requestCredentials(
        issuerMetadata: IssuerMetadata,
        jwtProofSigningAlgorithms: List<String>,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        getProofJwt: suspend (credentialIssuer: String, cNonce: String?, proofSigningAlgorithmsSupported: List<String>) -> String,
        credentialConfigurationId: String,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        offer: CredentialOffer,
    ): CredentialResponse {
        val authorizationServerMetadata = AuthorizationServerResolver().resolveForPreAuth(
            issuerMetadata = issuerMetadata,
            credentialOffer = offer
        )

        val tokenEndpoint = authorizationServerMetadata.tokenEndpoint
            ?: throw DownloadFailedException("Token endpoint is missing in Authorization Server metadata.")

        val grant = offer.grants?.preAuthorizedGrant
            ?: throw InvalidDataProvidedException("Missing pre-authorized grant details.")

        val txCode: String? = if (offer.grants.preAuthorizedGrant.txCode != null) {
            val txCodeInfo = offer.grants.preAuthorizedGrant.txCode
            getTxCode?.invoke(txCodeInfo.inputMode, txCodeInfo.description, txCodeInfo.length)
        } else null

        if (offer.grants.preAuthorizedGrant.txCode != null && txCode == null) {
            throw DownloadFailedException("tx_code required but no provider was given.")
        }

        val token = TokenService().getAccessToken(
            getTokenResponse = getTokenResponse,
            tokenEndpoint = tokenEndpoint,
            preAuthCode = grant.preAuthCode,
            txCode = txCode
        )

        val jwt = getProofJwt(
            issuerMetadata.credentialIssuer,
            token.cNonce,
            jwtProofSigningAlgorithms
        )

        val proof = JWTProof(jwt)

        return CredentialRequestExecutor().requestCredential(
            issuerMetadata,
            credentialConfigurationId,
            proof,
            accessToken = token.accessToken,
            downloadTimeoutInMillis
        ) ?: throw DownloadFailedException("Credential request failed.")

    }
}
