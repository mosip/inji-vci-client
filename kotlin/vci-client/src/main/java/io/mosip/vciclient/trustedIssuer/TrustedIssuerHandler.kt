package io.mosip.vciclient.trustedIssuer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

class TrustedIssuerHandler {
    suspend fun downloadCredentials(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        getProofJwt: suspend (
            credentialIssuer: String,
            cNonce: String?,
            proofSigningAlgosSupported: List<String>
        ) -> String,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        return AuthorizationCodeFlowService().requestCredentials(
            issuerMetadataResult = IssuerMetadataResult(
                issuerMetadata = issuerMetadata,
                raw = emptyMap()
            ),
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            authorizeUser = authorizeUser,
            getProofJwt = getProofJwt,
            credentialConfigurationId = credentialConfigurationId,
            downloadTimeOutInMillis = downloadTimeoutInMillis,
        )
    }
}
