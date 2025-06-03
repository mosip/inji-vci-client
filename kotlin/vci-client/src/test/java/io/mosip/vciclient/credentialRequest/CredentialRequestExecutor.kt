package io.mosip.vciclient.credentialRequest

import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.constants.CredentialFormat
import io.mockk.mockk
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit

class CredentialRequestExecutorTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var resolvedMeta: IssuerMetadata
    private val mockProof = mockk<Proof>()
    private val accessToken = "mock-access-token"

    @Before
    fun setup() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        resolvedMeta = IssuerMetadata(
            credentialAudience = "https://audience",
            credentialEndpoint = mockWebServer.url("/credential").toString(),
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
            MockResponse().setBody(json).setResponseCode(200).addHeader("Content-Type", "application/json")
        )

        val response = CredentialRequestExecutor("test").requestCredential(
            issuerMetadata = resolvedMeta,
            proof = mockProof,
            accessToken = accessToken
        )

        assertNotNull(response)
        assertTrue(response is CredentialResponse)
    }

    @Test
    fun `should return null when response body is empty`() {
        mockWebServer.enqueue(MockResponse().setBody("").setResponseCode(200))

        val result = CredentialRequestExecutor("test").requestCredential(
            resolvedMeta, mockProof, accessToken
        )

        assertNull(result)
    }

    @Test
    fun `should throw DownloadFailedException for non-200 response`() {
        mockWebServer.enqueue(
            MockResponse().setResponseCode(400).setBody("Bad Request")
        )

        val ex = assertThrows<DownloadFailedException> {
            CredentialRequestExecutor("test").requestCredential(
                resolvedMeta, mockProof, accessToken
            )
        }

        assertTrue(ex.message.contains("Bad Request"))
    }

    @Test
    fun `should throw NetworkRequestTimeoutException for delayed response`() {
        mockWebServer.enqueue(
            MockResponse().setBody("{}").setResponseCode(200).setBodyDelay(2, TimeUnit.SECONDS)
        )

        val ex = assertThrows<NetworkRequestTimeoutException> {
            CredentialRequestExecutor("test").requestCredential(
                resolvedMeta, mockProof, accessToken, downloadTimeoutInMilliSeconds = 500
            )
        }

        assertTrue(ex.message.contains("Download failed due to request timeout -"))

    }

    @Test
    fun `should throw NetworkRequestFailedException when network fails`() {
        mockWebServer.shutdown()

        val ex = assertThrows<NetworkRequestFailedException> {
            CredentialRequestExecutor().requestCredential(
                resolvedMeta, mockProof, accessToken
            )
        }

        assertNotNull(ex.message)
    }
}
