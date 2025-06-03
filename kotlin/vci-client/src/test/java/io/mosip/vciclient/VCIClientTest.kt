package io.mosip.vciclient

import android.content.Context
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.credentialRequestFlowHandlers.CredentialOfferHandler
import io.mosip.vciclient.credentialRequestFlowHandlers.TrustedIssuerHandler
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.VCIClientException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class VCIClientTest {

    private val mockCredentialResponse = mockk<CredentialResponse>()

    private lateinit var getTxCode: suspend (String?,String?,Int?) -> String
    private lateinit var getProofJwt: suspend (
        accessToken: String,
        cNonce: String?,
        issuerMetadata: Map<String, *>?,
        credentialConfigurationId: String?,
    ) -> String
    private lateinit var getAuthCode: suspend (authorizationEndpoint: String) -> String
    val  mockContext = mockk<Context>(relaxed = true)
    @Before
    fun setup() {


        mockkConstructor(CredentialOfferHandler::class)
        mockkConstructor(TrustedIssuerHandler::class)

        coEvery {
            anyConstructed<CredentialOfferHandler>().downloadCredentials(
                any(), any(), any(), any(), any(), any(),any(),any(),any()
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

        getProofJwt = object : suspend (String, String?, Map<String, *>?, String?) -> String {
            override suspend fun invoke(
                accessToken: String,
                cNonce: String?,
                issuerMetadata: Map<String, *>?,
                credentialConfigurationId: String?,
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
        val result = VCIClient("trace-id",mockContext).requestCredentialByCredentialOffer(
            credentialOffer = "sample-offer",
            clientMetadata = ClientMetadata("mock-id", "mock-redirect-ui"),
            getTxCode = getTxCode,
            getProofJwt = getProofJwt,
            getAuthCode = getAuthCode
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should return credential when trusted issuer flow succeeds`() = runBlocking {
        val result = VCIClient("trace-id", context = mockContext).requestCredentialFromTrustedIssuer(
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
                any(), any(), any(), any(), any(),any(),any(),any(),any()
            )
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            VCIClient("trace-id",mockContext).requestCredentialByCredentialOffer(
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
            VCIClient("trace-id", mockContext).requestCredentialFromTrustedIssuer(
                issuerMetadata = mockk(),
                clientMetadata = mockk(),
                getProofJwt = getProofJwt,
                getAuthCode = getAuthCode
            )
        }
    }
}
