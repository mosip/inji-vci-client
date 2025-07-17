package io.mosip.vciclient.trustedIssuer

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.pkce.PKCESessionManager.PKCESession
import io.mosip.vciclient.testData.wellKnownResponseMap
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import io.mosip.vciclient.types.AuthorizeUserCallback
import io.mosip.vciclient.types.ProofJwtCallback
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class TrustedIssuerFlowHandlerTest {

    private val mockCredentialResponse = mockk<CredentialResponse>()
    private val credentialIssuer = "https://example.com/issuer"
    private val credentialConfigurationId = "test-credential-config"
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val pkceSession = PKCESession("verifier", "challenge", "state", "nonce")
    private val authUrl = "https://auth/authorize?client_id=client-id"
    private val accessToken = "mockAccessToken"
    private val cNonce = "mockCNonce"

    private lateinit var authorizeUser: AuthorizeUserCallback
    private lateinit var getProofJwt: ProofJwtCallback

    @Before
    fun setup() {
        mockkConstructor(AuthorizationServerResolver::class)
        mockkConstructor(PKCESessionManager::class)
        mockkObject(AuthorizationUrlBuilder)
        mockkConstructor(TokenService::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkConstructor(IssuerMetadataService::class)

        every { anyConstructed<PKCESessionManager>().createSession() } returns pkceSession
        mockkObject(Util.Companion)
        every { Util.getLogTag(any(), any()) } returns "TestLogTag"
        coEvery { anyConstructed<IssuerMetadataService>().fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId) } returns IssuerMetadataResult(
            issuerMetadata = mockk<IssuerMetadata>(relaxed = true),
            raw = wellKnownResponseMap
        )

        every {
            AuthorizationUrlBuilder.build(
                any(), any(), any(), any(), any(), any(), any(), any(), any()
            )
        } returns authUrl

        authorizeUser = object : AuthorizeUserCallback {
            override suspend fun invoke(
                authEndpoint: String,
            ): String = "mock-auth-code"
        }

        getProofJwt = object : ProofJwtCallback {
            override suspend fun invoke(
                acredentialIssuer: String,
                cNonce: String?,
                proofSigningAlgorithmsSupported: List<String>
                ): String = "mock.jwt.proof"
        }

        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any())
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
            credentialIssuer = credentialIssuer,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = mockk(relaxed = true),
            authorizeUser = authorizeUser,
            getProofJwt = getProofJwt,
            downloadTimeoutInMillis = 10000
        )
        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw when getAuthCode throws`() = runBlocking {
        val failingAuthorizeUser: AuthorizeUserCallback = {
            throw IllegalStateException("User canceled")
        }

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                credentialIssuer = credentialIssuer,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = failingAuthorizeUser,
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("User canceled"))
    }

    @Test
    fun `should throw when getProofJwt throws`() = runBlocking {
        val failingProof: ProofJwtCallback =
            { _, _, _ ->
                throw IllegalArgumentException("Proof generation failed")
            }

        val ex = assertThrows<DownloadFailedException> {
            TrustedIssuerFlowHandler().downloadCredentials(
                credentialIssuer = credentialIssuer,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = authorizeUser,
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
                credentialIssuer = credentialIssuer,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = authorizeUser,
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
                credentialIssuer = credentialIssuer,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = mockk(relaxed = true),
                authorizeUser = authorizeUser,
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }

        assert(ex.message.contains("Credential request failed"))
    }
}
