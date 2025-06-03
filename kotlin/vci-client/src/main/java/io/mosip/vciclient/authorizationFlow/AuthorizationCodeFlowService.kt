package io.mosip.vciclient.authorizationFlow

import io.mosip.vciclient.authorizationServer.AuthServerMetadata
import io.mosip.vciclient.authorizationServer.AuthServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialRequest.CredentialRequestExecutor
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService

class AuthorizationCodeFlowService {

    suspend fun requestCredentials(
        issuerMetadataResult: IssuerMetadataResult,
        clientMetadata: ClientMetadata,
        offer: CredentialOffer? = null,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        getProofJwt: suspend (
            accessToken: String,
            cNonce: String?,
            issuerMetadata: Map<String, *>?,
            credentialConfigurationId: String?,
        ) -> String,
        credentialConfigurationId: String? = null,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
    ): CredentialResponse? {
        try {
            val pkceSession = PKCESessionManager().createSession()
            val authService = AuthServerResolver();
            val authServerMetadata: AuthServerMetadata = if (offer == null) {
                authService.resolveForAuthCode(issuerMetadataResult.issuerMetadata)
            } else
                authService.resolveForAuthCode(issuerMetadataResult.issuerMetadata, offer)

            val token = performAuthorizationAndGetToken(
                authServerMetadata,
                issuerMetadataResult.issuerMetadata,
                clientMetadata,
                getAuthCode,
                pkceSession
            )

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
                downloadTimeOutInMillis
            )
        } catch (e: Exception) {
            throw DownloadFailedException("Download failed by authorization code flow - ${e.message}")
        }

    }

    private suspend fun performAuthorizationAndGetToken(
        authServerMetadata: AuthServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        pkceSession: PKCESessionManager.PKCESession,
    ): TokenResponse {
        val authorizationEndpoint = authServerMetadata.authorizationEndpoint
            ?: throw DownloadFailedException("Authorization endpoint missing in authorization server metadata.")

        val tokenEndpoint = issuerMetadata.tokenEndpoint ?: authServerMetadata.tokenEndpoint
        ?: throw DownloadFailedException("Token endpoint missing in authorization server metadata.")


        val authUrl = AuthorizationUrlBuilder.build(
            baseUrl = authorizationEndpoint,
            clientId = clientMetadata.clientId,
            redirectUri = clientMetadata.redirectUri,
            scope = issuerMetadata.scope,
            state = pkceSession.state,
            codeChallenge = pkceSession.codeChallenge,
            nonce = pkceSession.nonce
        )

        val authCode = getAuthCode(authUrl)

        return TokenService().getAccessToken(
            tokenEndpoint = tokenEndpoint,
            authCode = authCode,
            clientId = clientMetadata.clientId,
            redirectUri = clientMetadata.redirectUri,
            codeVerifier = pkceSession.codeVerifier
        )
    }
}
