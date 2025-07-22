package io.mosip.vciclient.trustedIssuer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.constants.AuthorizeUserCallback
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.TokenResponseCallback

class TrustedIssuerFlowHandler {
    private val issuerMetadataService = IssuerMetadataService()
    private val authorizationCodeFlowService = AuthorizationCodeFlowService()

    suspend fun downloadCredentials(
        credentialIssuer: String,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: TokenResponseCallback,
        authorizeUser: AuthorizeUserCallback,
        getProofJwt: ProofJwtCallback,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        val issuerMetadataResult: IssuerMetadataResult = issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)

        return authorizationCodeFlowService.requestCredentials(
            issuerMetadata = issuerMetadataResult.issuerMetadata,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            authorizeUser = authorizeUser,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            downloadTimeOutInMillis = downloadTimeoutInMillis,
            jwtProofAlgorithmsSupported = issuerMetadataResult.extractJwtProofSigningAlgorithms(credentialConfigurationId),
        )
    }
}
