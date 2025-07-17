package io.mosip.vciclient.trustedIssuer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

class TrustedIssuerFlowHandler {
    private val issuerMetadataService = IssuerMetadataService()
    private val authorizationCodeFlowService = AuthorizationCodeFlowService()

    suspend fun downloadCredentials(
        credentialIssuer: String,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        getProofJwt: suspend (
            credentialIssuer: String,
            cNonce: String?,
            proofSigningAlgorithmsSupported: List<String>
        ) -> String,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        val issuerMetadataResult: IssuerMetadataResult = issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)

        return authorizationCodeFlowService.requestCredentials(
            issuerMetadataResult = issuerMetadataResult,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            authorizeUser = authorizeUser,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            downloadTimeOutInMillis = downloadTimeoutInMillis,
        )
    }
}
