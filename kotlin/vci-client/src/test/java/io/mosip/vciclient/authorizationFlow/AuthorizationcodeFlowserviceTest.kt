package io.mosip.vciclient.authorizationFlow

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationServer.AuthServerMetadata
import io.mosip.vciclient.authorizationServer.AuthServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.pkce.PKCESessionManager.PKCESession
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class AuthorizationCodeFlowServiceTest {
    private val downloadTimeout: Long = 5000L
    private val mockCredentialResponse = mockk<CredentialResponse>()
    private val resolvedMeta = mockk<IssuerMetadata>(relaxed = true) {
        every { scope } returns "openid"
    }
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val credentialOffer = mockk<CredentialOffer>()
    private val issuerMetadata = mapOf("some" to "value")
    private val credentialConfigurationId = "UniversityDegreeCredential"
    private val pkceSession = PKCESession("verifier", "challenge", "state", "nonce")

    private lateinit var authorizeUser: suspend (String) -> String
    private lateinit var getProofJwt: suspend (String, String?, List<String>) -> String
    private lateinit var getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse


    @Before
    fun setup() {
        mockkObject(Util)
        every { Util.getLogTag(any(), null) } returns "mocked-tag"

        mockkConstructor(PKCESessionManager::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkConstructor(AuthServerResolver::class)
        mockkObject(AuthorizationUrlBuilder)
        mockkConstructor(TokenService::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkConstructor(JWTProof::class)

        every { anyConstructed<PKCESessionManager>().createSession() } returns pkceSession
        every { anyConstructed<CredentialRequestExecutor>().requestCredential(any(), any(), any(), any(), any()) } returns mockCredentialResponse

        coEvery {
            anyConstructed<AuthServerResolver>().resolveForAuthCode(
                any(),
                any()
            )
        } returns mockk<AuthServerMetadata> {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
        }

        every {
            AuthorizationUrlBuilder.build(
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns "https://auth.example.com/authorize"

        coEvery {
            anyConstructed<TokenService>().getAccessToken(any(), any(), any(), any(), any(), any())
        } returns TokenResponse("mockAccessToken", "jwt", expiresIn = 3600, cNonce = "mockCNonce")

        every {
            anyConstructed<JWTProof>().jwt
        } returns "mock.jwt.proof"

        every {
            anyConstructed<CredentialRequestExecutor>().requestCredential(
                any(),
                any(),
                any(),
                any()
            )
        } returns mockCredentialResponse

        authorizeUser = { _ -> "mockAuthCode" }
        getProofJwt = { _, _, _ -> "mock.jwt.proof" }
        getTokenResponse = { _ -> TokenResponse("accessToken", "accessToken") }
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential when flow is successful`() = runBlocking {
        val result = AuthorizationCodeFlowService().requestCredentials(
            issuerMetadataResult = IssuerMetadataResult(resolvedMeta, issuerMetadata),
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            authorizeUser = authorizeUser,
            getProofJwt = getProofJwt,
            credentialConfigurationId = credentialConfigurationId,
            credentialOffer = credentialOffer,
            downloadTimeOutInMillis = downloadTimeout
        )

        assertEquals(mockCredentialResponse, result)
    }


    @Test
    fun `should throw when token service fails`() {
        runBlocking {
            coEvery {
                anyConstructed<TokenService>().getAccessToken(
                    any(),
                    any(),
                    any(),
                    any(),
                    any(),
                    any()
                )
            } throws Exception("Token service failure")

            val downloadFailureException = assertThrows<DownloadFailedException> {
                AuthorizationCodeFlowService().requestCredentials(
                    issuerMetadataResult = IssuerMetadataResult(
                        issuerMetadata = resolvedMeta,
                        raw = issuerMetadata
                    ),
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    authorizeUser = authorizeUser,
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigurationId,
                    credentialOffer = credentialOffer,
                    downloadTimeOutInMillis = downloadTimeout
                )
            }

            assertEquals("Download failed via authorization code flow: Token service failure", downloadFailureException.message)
        }
    }
}
