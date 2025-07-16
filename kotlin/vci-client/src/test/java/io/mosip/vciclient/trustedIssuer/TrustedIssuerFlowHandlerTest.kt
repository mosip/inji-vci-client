package io.mosip.vciclient.trustedIssuer

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationServer.AuthServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.pkce.PKCESessionManager.PKCESession
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class TrustedIssuerFlowHandlerTest {

    private val mockCredentialResponse = mockk<CredentialResponse>()
    private val resolvedMeta = mockk<IssuerMetadata>(relaxed = true)
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val pkceSession = PKCESession("verifier", "challenge", "state", "nonce")
    private val authUrl = "https://auth/authorize?client_id=client-id"
    private val accessToken = "mockAccessToken"
    private val cNonce = "mockCNonce"

    private lateinit var getAuthCode: suspend (String) -> String
    private lateinit var getProofJwt: suspend (
        credentialIssuer: String,
        cNonce: String?,
        proofSigningAlgosSupported: List<String>
    ) -> String

    @Before
    fun setup() {
        mockkConstructor(AuthServerResolver::class)
        mockkConstructor(PKCESessionManager::class)
        mockkObject(AuthorizationUrlBuilder)
        mockkConstructor(TokenService::class)
        mockkConstructor(CredentialRequestExecutor::class)

        every { anyConstructed<PKCESessionManager>().createSession() } returns pkceSession
        mockkObject(Util.Companion)
        every { Util.getLogTag(any(), any()) } returns "TestLogTag"

        every {
            AuthorizationUrlBuilder.build(
                any(), any(), any(), any(), any(), any(), any(), any(), any()
            )
        } returns authUrl

        getAuthCode = object : suspend (String) -> String {
            override suspend fun invoke(
                authEndpoint: String,
            ): String = "mock-auth-code"
        }

        getProofJwt = object : suspend (String, String?, List<String>) -> String {
            override suspend fun invoke(
                acredentialIssuer: String,
                cNonce: String?,
                proofSigningAlgosSupported: List<String>
                ): String = "mock.jwt.proof"
        }

        coEvery {
            anyConstructed<AuthServerResolver>().resolveForAuthCode(any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth/authorize"
            every { tokenEndpoint } returns "https://auth/token"
        }

        coEvery {
            anyConstructed<TokenService>().getAccessToken(any(), any(), any(), any(), any(), any())
        } returns TokenResponse(accessToken, "jwt", cNonce = cNonce)

        every {
            anyConstructed<CredentialRequestExecutor>().requestCredential(any(), any(), any(), any(), any())
        } returns mockCredentialResponse
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential on successful flow`() = runBlocking {
        val result = TrustedIssuerFlowHandler().downloadCredentials(
            issuerMetadata = resolvedMeta,
            credentialConfigurationId = "test-credential-config",
            clientMetadata = clientMetadata,
            getTokenResponse = mockk(relaxed = true),
            authorizeUser = getAuthCode,
            getProofJwt = getProofJwt,
            downloadTimeoutInMillis = 10000
        )
        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw when getAuthCode throws`() = runBlocking {
        val failingGetAuthCode: suspend (String) -> String = {
            throw IllegalStateException("User canceled")
        }

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                issuerMetadata = resolvedMeta,
                credentialConfigurationId = "test-credential-config",
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = failingGetAuthCode,
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("User canceled"))
    }

    @Test
    fun `should throw when getProofJwt throws`() = runBlocking {
        val failingProof: suspend (String, String?, List<String>) -> String =
            { _, _, _ ->
                throw IllegalArgumentException("Proof generation failed")
            }

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                issuerMetadata = resolvedMeta,
                credentialConfigurationId = "test-credential-config",
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = getAuthCode,
                getProofJwt = failingProof,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("Proof generation failed"))
    }

    @Test
    fun `should throw when token service fails`() = runBlocking {
        coEvery {
            anyConstructed<TokenService>().getAccessToken(any(), any(), any(), any(), any(), any())
        } throws DownloadFailedException("Token error")

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                issuerMetadata = resolvedMeta,
                credentialConfigurationId = "test-credential-config",
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = getAuthCode,
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("Token error"))
    }

    @Test
    fun `should throw when credential request executor fails`() = runBlocking {
        every {
            anyConstructed<CredentialRequestExecutor>().requestCredential(any(), any(), any(), any(), any())
        } throws DownloadFailedException("Credential request failed")

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                issuerMetadata = resolvedMeta,
                credentialConfigurationId = "test-credential-config",
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = getAuthCode,
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("Credential request failed"))
    }
}
