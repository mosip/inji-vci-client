package io.mosip.vciclient.authorizationCodeFlow

import extractProofSigningAlgorithms
import io.mosip.vciclient.authorizationServer.AuthServerMetadata
import io.mosip.vciclient.authorizationServer.AuthServerResolver
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

class AuthorizationCodeFlowService(
    private val authServerResolver: AuthServerResolver = AuthServerResolver(),
    private val tokenService: TokenService = TokenService(),
    private val credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
    private val pkceSessionManager: PKCESessionManager = PKCESessionManager()
) {

    suspend fun requestCredentials(
        issuerMetadataResult: IssuerMetadataResult,
        clientMetadata: ClientMetadata,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        getProofJwt: suspend (
            credentialIssuer: String,
            cNonce: String?,
            proofSigningAlgosSupported: List<String>
        ) -> String,
        credentialConfigurationId: String,
        credentialOffer: CredentialOffer? = null,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        try {
            val pkceSession = pkceSessionManager.createSession()

            val authServerMetadata = authServerResolver.resolveForAuthCode(
                issuerMetadataResult.issuerMetadata,
                credentialOffer
            )

            val token = performAuthorizationAndGetToken(
                authServerMetadata = authServerMetadata,
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                clientMetadata = clientMetadata,
                authorizeUser = authorizeUser,
                pkceSession = pkceSession,
                getTokenResponse = getTokenResponse
            )

            val proofSigningAlgosSupported = extractProofSigningAlgorithms(
                issuerMetadataResult.raw as Map<String, Any>,
                credentialConfigurationId
            )
            val jwt = getProofJwt(
                issuerMetadataResult.issuerMetadata.credentialIssuer,
                token.cNonce,
                proofSigningAlgosSupported
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
        authServerMetadata: AuthServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        pkceSession: PKCESessionManager.PKCESession,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse
    ): TokenResponse {
        val authorizationEndpoint = authServerMetadata.authorizationEndpoint
            ?: throw DownloadFailedException("Missing authorization endpoint")

        val tokenEndpoint = issuerMetadata.tokenEndpoint ?: authServerMetadata.tokenEndpoint
        ?: throw DownloadFailedException("Missing token endpoint")

        val authUrl = AuthorizationUrlBuilder.build(
            baseUrl = authorizationEndpoint,
            clientId = clientMetadata.clientId,
            redirectUri = clientMetadata.redirectUri,
            scope = issuerMetadata.scope ?: "",
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