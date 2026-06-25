package io.mosip.vciclient.credential.request

import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit

class CredentialRequestExecutorTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var resolvedMeta: IssuerMetadata
    private val mockProof = JWTProof("headerEncoded.payloadEncoded.signature")
    private val accessToken = "mock-access-token"

    @Before
    fun setup() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        resolvedMeta = IssuerMetadata(
            credentialIssuer = "https://audience",
            credentialEndpoint = mockWebServer.url("/io/mosip/vciclient/credential").toString(),
            credentialFormat = CredentialFormat.LDP_VC,
            credentialType = listOf("VerifiableCredential"),
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            authorizationServers = emptyList()
        )
    }

    @After
    fun teardown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `should return CredentialResponse on successful fetch`() {
        val json = """{"credential": "mock"}"""
        mockWebServer.enqueue(
            MockResponse().setBody(json).setResponseCode(200).addHeader(CONTENT_TYPE, APPLICATION_JSON)
        )
        val response = CredentialRequestExecutor().requestCredentialDraft13(
            issuerMetadata = resolvedMeta,
            credentialConfigurationId = "SampleCredential",
            proof = mockProof,
            accessToken = accessToken
        )

        assertNotNull(response)
        assertTrue(response is CredentialResponseDraft13)
    }

    @Test
    fun `should return v1 CredentialResponse on successful fetch`() {
        val json = """{"credentials":[{"credential":"credential-1"}]}"""
        mockWebServer.enqueue(
            MockResponse().setBody(json).setResponseCode(200).addHeader(CONTENT_TYPE, APPLICATION_JSON)
        )

        val response = CredentialRequestExecutor().requestCredential(
            issuerMetadata = resolvedMeta.copy(credentialFormat = CredentialFormat.LDP_VC),
            credentialConfigurationId = "SampleCredential",
            proofs = CredentialRequestProofs(proofs = listOf("proof-1")),
            accessToken = accessToken
        )

        assertNotNull(response)
        assertEquals("SampleCredential", response?.credentialConfigurationId)
        assertEquals("https://audience", response?.credentialIssuer)
        assertEquals(1, response?.credentials?.size)
    }

    @Test
    fun `should return null when response body is empty`() {
        mockWebServer.enqueue(MockResponse().setBody("").setResponseCode(200))

        val result = CredentialRequestExecutor().requestCredentialDraft13(
            resolvedMeta,"SampleCredential", mockProof, accessToken
        )

        assertNull(result)
    }

    @Test
    fun `should return null when v1 response body is empty`() {
        mockWebServer.enqueue(MockResponse().setBody("").setResponseCode(200))

        val result = CredentialRequestExecutor().requestCredential(
            issuerMetadata = resolvedMeta.copy(credentialFormat = CredentialFormat.LDP_VC),
            credentialConfigurationId = "SampleCredential",
            proofs = CredentialRequestProofs(proofs = listOf("proof-1")),
            accessToken = accessToken
        )

        assertNull(result)
    }

    @Test
    fun `should throw DownloadFailedException for non-200 response`() {
        mockWebServer.enqueue(
            MockResponse().setResponseCode(400).setBody("Bad Request")
        )

        val ex = assertThrows<DownloadFailedException> {
            CredentialRequestExecutor().requestCredentialDraft13(
                resolvedMeta,"SampleCredential", mockProof, accessToken
            )
        }
        assertTrue(ex.issuerErrorDescription?.contains("Bad Request") == true)
    }

    @Test
    fun `should throw DownloadFailedException for delayed response`() {
        mockWebServer.enqueue(
            MockResponse().setBody("{}").setResponseCode(200).setBodyDelay(2, TimeUnit.SECONDS)
        )

        val ex = assertThrows<DownloadFailedException> {
            CredentialRequestExecutor().requestCredentialDraft13(
                resolvedMeta,"SampleCredential", mockProof, accessToken, downloadTimeoutInMillis = 500
            )
        }
        assertTrue(ex.message.contains("Credential download timed out after"))

    }

    @Test
    fun `should throw NetworkRequestFailedException when network fails`() {
        mockWebServer.enqueue(
            MockResponse()
                .setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START)
        )

        val ex = assertThrows<DownloadFailedException> {
            CredentialRequestExecutor().requestCredentialDraft13(
                resolvedMeta, "SampleCredential",mockProof, accessToken
            )
        }

        assertNotNull(ex.message)
    }

    @Test
    fun `should propagate server error code and description with cause from NetworkManager`() {
        val errorJson = """{"error":"invalid_proof","error_description":"proof is missing"}"""
        mockWebServer.enqueue(
            MockResponse().setResponseCode(400).setBody(errorJson)
        )

        val ex = assertThrows<DownloadFailedException> {
            CredentialRequestExecutor().requestCredentialDraft13(
                issuerMetadata = resolvedMeta,
                credentialConfigurationId = "SampleCredential",
                proof = mockProof,
                accessToken = accessToken
            )
        }

        assertTrue(ex.cause is NetworkRequestFailedException)
        assertTrue(ex.message.contains("HTTP 400"))
        assertTrue(ex.issuerErrorCode == "invalid_proof")
        assertTrue(ex.issuerErrorDescription == "proof is missing")
    }
}
