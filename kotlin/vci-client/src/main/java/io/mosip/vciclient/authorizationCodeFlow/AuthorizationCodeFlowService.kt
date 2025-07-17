package io.mosip.vciclient.authorizationCodeFlow

import io.mosip.vciclient.authorizationServer.AuthorizationServerMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService

internal class AuthorizationCodeFlowService(
    private val authorizationServerResolver: AuthorizationServerResolver = AuthorizationServerResolver(),
    private val tokenService: TokenService = TokenService(),
    private val credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
    private val pkceSessionManager: PKCESessionManager = PKCESessionManager()
) {

    suspend fun requestCredentials(
        issuerMetadataResult: IssuerMetadataResult,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        getProofJwt: suspend (credentialIssuer: String, cNonce: String?, proofSigningAlgorithmsSupported: List<String>) -> String,
        credentialOffer: CredentialOffer? = null,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        try {
            val pkceSession = pkceSessionManager.createSession()

            val authorizationServerMetadata = authorizationServerResolver.resolveForAuthCode(
                issuerMetadataResult.issuerMetadata,
                credentialOffer
            )

            val token = performAuthorizationAndGetToken(
                authorizationServerMetadata = authorizationServerMetadata,
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                clientMetadata = clientMetadata,
                authorizeUser = authorizeUser,
                pkceSession = pkceSession,
                getTokenResponse = getTokenResponse
            )

            val jwt = getProofJwt(
                issuerMetadataResult.issuerMetadata.credentialIssuer,
                token.cNonce,
                issuerMetadataResult.extractJwtProofSigningAlgorithms(credentialConfigurationId)
            )

            val proof = JWTProof(jwt)

            return credentialExecutor.requestCredential(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proof = proof,
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeOutInMillis
            ) ?: throw DownloadFailedException("Credential request returned null.")

        } catch (e: Exception) {
            throw DownloadFailedException("Download failed via authorization code flow: ${e.message}")
        }
    }

    private suspend fun performAuthorizationAndGetToken(
        authorizationServerMetadata: AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        pkceSession: PKCESessionManager.PKCESession,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse
    ): TokenResponse {
        val authorizationEndpoint = authorizationServerMetadata.authorizationEndpoint
            ?: throw DownloadFailedException("Missing authorization endpoint")

        val tokenEndpoint = issuerMetadata.tokenEndpoint ?: authorizationServerMetadata.tokenEndpoint
        ?: throw DownloadFailedException("Missing token endpoint")

        val authUrl = AuthorizationUrlBuilder.build(
            baseUrl = authorizationEndpoint,
            clientId = clientMetadata.clientId,
            redirectUri = clientMetadata.redirectUri,
            scope = issuerMetadata.scope,
            state = pkceSession.state,
            codeChallenge = pkceSession.codeChallenge,
            nonce = pkceSession.nonce
        )

        val authCode = authorizeUser(authUrl)

        return tokenService.getAccessToken(
            getTokenResponse = getTokenResponse,
            tokenEndpoint = tokenEndpoint,
            authCode = authCode,
            clientId = clientMetadata.clientId,
            redirectUri = clientMetadata.redirectUri,
            codeVerifier = pkceSession.codeVerifier
        )
    }
}