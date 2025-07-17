package io.mosip.vciclient.credentialOffer

import com.google.gson.JsonNull
import com.google.gson.JsonPrimitive
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class CredentialOfferFlowHandlerTest {
    private val mockCredentialResponse = CredentialResponse(
        JsonPrimitive("dummy-credential"),
        "SampleCredential",
        "https://issuer.example.com/issuer"
    )
    private val mockCredentialOffer = mockk<CredentialOffer>()
    private val mockIssuerMetadataResult = mockk<IssuerMetadataResult>()
    private val mockClientMetadata = mockk<ClientMetadata>()

    private lateinit var txCode: suspend (String?, String?, Int?) -> String
    private lateinit var getProofJwt: suspend (String, String?, List<String>) -> String
    private lateinit var authorizeUser: suspend (String) -> String
    private lateinit var getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse
    private lateinit var onCheckIssuerTrust: suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean


    @Before
    fun setup() {
        mockkConstructor(CredentialOfferService::class)
        mockkConstructor(IssuerMetadataService::class)
        mockkConstructor(PreAuthCodeFlowService::class)
        mockkConstructor(AuthorizationCodeFlowService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns mockCredentialOffer
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchIssuerMetadataResult(
                any(),
                any()
            )
        } returns mockIssuerMetadataResult
        every { mockIssuerMetadataResult.issuerMetadata } returns mockk(relaxed = true)
        every { mockIssuerMetadataResult.raw } returns mapOf("some" to "metadata")
        txCode = object : suspend (String?, String?, Int?) -> String {
            override suspend fun invoke(
                p1: String?, p2: String?, p3: Int?
            ): String = "mock-auth-code"
        }
        authorizeUser = object : suspend (String) -> String {
            override suspend fun invoke(
                authEndpoint: String,
            ): String = "mock-auth-code"
        }

        getProofJwt = object : suspend (String, String?, List<String>) -> String {
            override suspend fun invoke(p1: String, p2: String?, p3: List<String>): String =
                "mock.jwt.proof"
        }
        onCheckIssuerTrust = mockk()
        getTokenResponse = { _ -> TokenResponse("accessToken", "accessToken") }
        coEvery { onCheckIssuerTrust.invoke(any(), any()) } returns true
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential for pre-authorized flow`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentials(
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns mockCredentialResponse

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        val result = CredentialOfferFlowHandler().downloadCredentials(
            credentialOffer = "some-offer",
            clientMetadata = mockClientMetadata,
            getTxCode = txCode,
            authorizeUser = authorizeUser,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            onCheckIssuerTrust = onCheckIssuerTrust,
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw if flow type is not supported`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(null, null)
        )

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<CredentialOfferFetchFailedException> {
            CredentialOfferFlowHandler().downloadCredentials(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                getTxCode = txCode,
                authorizeUser = authorizeUser,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                onCheckIssuerTrust = onCheckIssuerTrust,
            )
        }
    }

    @Test
    fun `should throw if no credential is returned`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentials(
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns CredentialResponse(
            JsonNull.INSTANCE,
            "SampleCredential",
            "https://issuer.example.com/issuer"
        )

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<CredentialOfferFetchFailedException> {
            CredentialOfferFlowHandler().downloadCredentials(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                getTxCode = txCode,
                authorizeUser = authorizeUser,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                onCheckIssuerTrust = onCheckIssuerTrust,
            )
        }
    }

    @Test
    fun `should throw if user does not give trust consent for untrusted issuer`(): Unit =
        runBlocking {
            val offer = CredentialOffer(
                credentialIssuer = "https://issuer.example.com",
                credentialConfigurationIds = listOf("UniversityDegreeCredential"),
                grants = CredentialOfferGrants(
                    preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                    authorizationCodeGrant = null
                )
            )

            coEvery { onCheckIssuerTrust.invoke(any(), any()) } returns false

            coEvery {
                anyConstructed<CredentialOfferService>().fetchCredentialOffer(any())
            } returns offer

            assertThrows<CredentialOfferFetchFailedException> {
                CredentialOfferFlowHandler().downloadCredentials(
                    credentialOffer = "some-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    authorizeUser = authorizeUser,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    onCheckIssuerTrust = onCheckIssuerTrust,
                )
            }
        }

    @Test
    fun `should throw batch credential not supported exception when the provided credential offer contains more than one credentialConfigurationIds`() =
        runBlocking {
            val offer = CredentialOffer(
                credentialIssuer = "https://issuer.example.com",
                credentialConfigurationIds = listOf(
                    "UniversityDegreeCredential",
                    "CollegeTranscriptCredential"
                ),
                grants = CredentialOfferGrants(
                    preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                    authorizationCodeGrant = null
                )
            )
            coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

            val downloadFailedException = assertThrows<DownloadFailedException> {
                CredentialOfferFlowHandler().downloadCredentials(
                    credentialOffer = "some-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    authorizeUser = authorizeUser,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    onCheckIssuerTrust = onCheckIssuerTrust,
                )
            }

            assertEquals("Failed to download Credential: Batch credential request is not supported.", downloadFailedException.message)
        }
}
