package io.mosip.vciclient.credentialRequestFlowHandlers

import io.mosip.vciclient.authorizationFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult

class TrustedIssuerHandler {
    suspend fun downloadCredentials(
        resolvedMeta: IssuerMetadata,
        clientMetadata: ClientMetadata,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        getProofJwt: suspend (
            accessToken: String,
            cNonce: String?,
            issuerMetadata: Map<String, *>?,
            credentialConfigurationId: String?,
        ) -> String,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
    ): CredentialResponse? {
        return AuthorizationCodeFlowService().requestCredentials(
            issuerMetadataResult = IssuerMetadataResult(
                issuerMetadata = resolvedMeta,
                raw = emptyMap()
            ),
            clientMetadata = clientMetadata,
            getAuthCode = getAuthCode,
            getProofJwt = getProofJwt,
            downloadTimeOutInMillis = downloadTimeOutInMillis,
            traceabilityId = traceabilityId
        )
    }
}
