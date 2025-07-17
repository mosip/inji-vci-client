package io.mosip.vciclient

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.credentialOffer.CredentialOfferFlowHandler
import io.mosip.vciclient.trustedIssuer.TrustedIssuerFlowHandler
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.IssuerMetadataFetchException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.proof.Proof
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class VCIClientTest {

    private val mockCredentialResponse = mockk<CredentialResponse>()

    private lateinit var getTxCode: suspend (String?, String?, Int?) -> String
    private lateinit var getProofJwt: suspend (
        credentialIssuer: String,
        cNonce: String?,
        proofSigningAlgorithmsSupported: List<String>
    ) -> String
    private lateinit var getAuthCode: suspend (authorizationEndpoint: String) -> String

    @Before
    fun setup() {


        mockkConstructor(CredentialOfferFlowHandler::class)
        mockkConstructor(TrustedIssuerFlowHandler::class)
        mockkConstructor(IssuerMetadataService::class)

        coEvery {
            anyConstructed<CredentialOfferFlowHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any(), any(), any()
            )
        } returns mockCredentialResponse

        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any()
            )
        } returns mockCredentialResponse

        getTxCode = object : suspend (String?, String?, Int?) -> String {
            override suspend fun invoke(p1: String?, p2: String?, p3: Int?): String = "mockTxCode"
        }

        getProofJwt = object : suspend (String, String?, List<String>) -> String {
            override suspend fun invoke(
                credentialIssuer: String,
                cNonce: String?,
                proofSigningAlgorithmsSupported: List<String>
            ): String = "mock.jwt.proof"
        }


        getAuthCode = object : suspend (String) -> String {
            override suspend fun invoke(authEndpoint: String): String = "mockAuthCode"
        }

    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should return issuerMetadata result on getIssuerMetadata`() {
        val mockIssuerMetadata = emptyMap<String, String>()
        coEvery {
            anyConstructed<IssuerMetadataService>()
                .fetchAndParseIssuerMetadata(any())
        } returns mockIssuerMetadata

        val issuerMetadataResult: Map<String, Any> = VCIClient("trace-id").getIssuerMetadata(
            credentialIssuer = "https://example.com/issuer"
        )

        assertEquals(mockIssuerMetadata, issuerMetadataResult)
    }

    @Test
    fun `should throw VCIClient unknown exception on getIssuerMetadata when unexpected error occurred`() {
        coEvery {
            anyConstructed<IssuerMetadataService>()
                .fetchAndParseIssuerMetadata(any())
        } throws RuntimeException("Unexpected error")

        val vciClientException = assertThrows<VCIClientException> {
            VCIClient("trace-id").getIssuerMetadata(
                credentialIssuer = "https://example.com/issuer"
            )
        }
        assertEquals("Unknown Exception - Unexpected error", vciClientException.message)
    }

    @Test
    fun `should throw VCIClient exception on getIssuerMetadata when any VCIClient exception occurred`() {
        coEvery {
            anyConstructed<IssuerMetadataService>()
                .fetchAndParseIssuerMetadata(any())
        } throws IssuerMetadataFetchException("Failed to fetch metadata")

        val vciClientException = assertThrows<IssuerMetadataFetchException> {
            VCIClient("trace-id").getIssuerMetadata(
                credentialIssuer = "https://example.com/issuer"
            )
        }
        assertEquals("Failed to fetch issuerMetadata - Failed to fetch metadata", vciClientException.message)
    }

    @Test
    fun `should return credential when credential offer flow succeeds`() = runBlocking {
        val result = VCIClient("trace-id").requestCredentialByCredentialOffer(
            credentialOffer = "sample-offer",
            clientMetadata = mockk(),
            getTxCode = getTxCode,
            authorizeUser = getAuthCode,
            getTokenResponse = mockk(relaxed = true),
            getProofJwt = getProofJwt,
            onCheckIssuerTrust = mockk(relaxed = true),
            downloadTimeoutInMillis = 10000
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should return credential when trusted issuer flow succeeds`() = runBlocking {
        // Create a mock IssuerMetadata result
        val mockIssuerMetadata = mockk<IssuerMetadata>(relaxed = true)
        val mockMetadataResult = mockk<IssuerMetadataResult> {
            every { issuerMetadata } returns mockIssuerMetadata
        }

        coEvery {
            anyConstructed<IssuerMetadataService>()
                .fetchIssuerMetadataResult(any(), any())
        } returns mockMetadataResult

        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any(), any()
            )
        } returns mockCredentialResponse

        val result = VCIClient("trace-id").requestCredentialFromTrustedIssuer(
            credentialIssuer = "https://example.com/issuer",
            credentialConfigurationId = "config-id",
            clientMetadata = mockk(),
            authorizeUser = getAuthCode,
            getTokenResponse = mockk(relaxed = true),
            getProofJwt = getProofJwt,
            downloadTimeoutInMillis = 10000
        )
        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw VCIClientException when credential offer flow throws`(): Unit = runBlocking {
        coEvery {
            anyConstructed<CredentialOfferFlowHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any(), any(), any()
            )
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            VCIClient("trace-id").requestCredentialByCredentialOffer(
                credentialOffer = "sample-offer",
                clientMetadata = mockk(),
                getTxCode = getTxCode,
                authorizeUser = getAuthCode,
                getTokenResponse = mockk(relaxed = true),
                getProofJwt = getProofJwt,
                onCheckIssuerTrust = mockk(),
                downloadTimeoutInMillis = 10000
            )
        }
    }

    @Test
    fun `should throw VCIClientException when trusted issuer flow throws`(): Unit = runBlocking {
        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any()
            )
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            VCIClient("trace-id").requestCredentialFromTrustedIssuer(
                credentialIssuer = "https://example.com/issuer",
                credentialConfigurationId = "config-id",
                clientMetadata = mockk(),
                authorizeUser = getAuthCode,
                getTokenResponse = mockk(relaxed = true),
                getProofJwt = getProofJwt,
                downloadTimeoutInMillis = 10000
            )
        }
    }

    @Test
    fun `should return credential when requestCredential succeeds`() {
        // Arrange
        val mockIssuerMetaData = mockk<IssuerMetaData> {
            every { credentialAudience } returns "audience"
            every { credentialEndpoint } returns "https://example.com"
            every { credentialType } returns arrayOf("test-type")
            every { credentialFormat } returns CredentialFormat.LDP_VC
            every { doctype } returns "test-doctype"
            every { claims } returns emptyMap()
            every { downloadTimeoutInMilliSeconds } returns 30000
        }

        val mockProof = mockk<Proof>(relaxed = true)

        mockkConstructor(OkHttpClient.Builder::class)
        val mockClient = mockk<OkHttpClient>(relaxed = true)
        val mockCall = mockk<okhttp3.Call>(relaxed = true)
        val mockResponseBody = mockk<okhttp3.ResponseBody>(relaxed = true)
        val mockResponse = mockk<okhttp3.Response>()

        every {
            anyConstructed<OkHttpClient.Builder>().callTimeout(
                any<Long>(),
                any()
            )
        } returns OkHttpClient.Builder()
        every { anyConstructed<OkHttpClient.Builder>().build() } returns mockClient
        every { mockClient.newCall(any()) } returns mockCall
        every { mockCall.execute() } returns mockResponse
        every { mockResponse.code } returns 200
        every { mockResponse.body } returns mockResponseBody
        every { mockResponseBody.byteStream() } returns """
        {"credential":"test"}
    """.trimIndent().byteInputStream()

        val result = VCIClient("trace-id").requestCredential(
            issuerMetadata = mockIssuerMetaData,
            proof = mockProof,
            accessToken = "dummy-access-token"
        )

        assertEquals("test", result?.credential?.asString)
    }

}
