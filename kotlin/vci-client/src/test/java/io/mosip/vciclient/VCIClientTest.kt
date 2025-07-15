package io.mosip.vciclient

import android.content.Context
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.credentialOffer.CredentialOfferHandler
import io.mosip.vciclient.trustedIssuer.TrustedIssuerHandler
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.VCIClientException
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

    private lateinit var getTxCode: suspend (String?,String?,Int?) -> String
    private lateinit var getProofJwt: suspend (
        credentialIssuer: String,
        cNonce: String?,
        proofSigningAlgosSupported: List<String>
    ) -> String
    private lateinit var getAuthCode: suspend (authorizationEndpoint: String) -> String
    val  mockContext = mockk<Context>(relaxed = true)
    @Before
    fun setup() {


        mockkConstructor(CredentialOfferHandler::class)
        mockkConstructor(TrustedIssuerHandler::class)

        coEvery {
            anyConstructed<CredentialOfferHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any(),any(),any()
            )
        } returns mockCredentialResponse

        coEvery {
            anyConstructed<TrustedIssuerHandler>().downloadCredentials(
                any(), any(), any(), any(),any(),any()
            )
        } returns mockCredentialResponse

        getTxCode = object : suspend (String?,String?,Int?) -> String {
             override suspend fun invoke(p1:String?,p2:String?,p3:Int?): String = "mockTxCode"
        }

        getProofJwt = object : suspend (String, String?, List<String) -> String {
            override suspend fun invoke(
                credentialIssuer: String,
                cNonce: String?,
                proofSigningAlgosSupported: List<String>
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
        val result = VCIClient("trace-id").requestCredentialFromTrustedIssuer(
            issuerMetadata = mockk(),
            clientMetadata = mockk(),
            getProofJwt = getProofJwt,
            getAuthCode = getAuthCode
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw VCIClientException when credential offer flow throws`(): Unit = runBlocking {
        coEvery {
            anyConstructed<CredentialOfferHandler>().downloadCredentials(
                any(), any(), any(), any(), any(),any(),any(),any()
            )
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            VCIClient("trace-id").requestCredentialByCredentialOffer(
                credentialOffer = "sample-offer",
                clientMetadata = mockk(),
                getTxCode = getTxCode,
                getProofJwt = getProofJwt,
                getAuthCode = getAuthCode
            )
        }
    }

    @Test
    fun `should throw VCIClientException when trusted issuer flow throws`(): Unit = runBlocking {
        coEvery {
            anyConstructed<TrustedIssuerHandler>().downloadCredentials(
                any(), any(), any(), any(),any(),any()
            )
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            VCIClient("trace-id").requestCredentialFromTrustedIssuer(

                issuerMetadata = mockk(),
                clientMetadata = mockk(),
                getProofJwt = getProofJwt,
                getAuthCode = getAuthCode
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

        every { anyConstructed<OkHttpClient.Builder>().callTimeout(any<Long>(), any()) } returns OkHttpClient.Builder()
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
