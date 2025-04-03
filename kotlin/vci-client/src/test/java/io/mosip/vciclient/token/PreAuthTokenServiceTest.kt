package io.mosip.vciclient.token

import PreAuthTokenService
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class PreAuthTokenServiceTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var service: PreAuthTokenService

    private val sampleTokenJson = """
        {
            "access_token": "sample-token",
            "token_type": "Bearer",
            "expires_in": 600,
            "c_nonce": "sample-cnonce",
            "c_nonce_expires_in": 300
        }
    """.trimIndent()

    private fun createValidIssuerMetaData(): IssuerMetaData {
        return IssuerMetaData(
            credentialAudience = "https://aud.example.com",
            credentialEndpoint = "https://example.com/credential",
            downloadTimeoutInMilliSeconds = 5000,
            credentialType = arrayOf("VerifiableCredential"),
            credentialFormat = io.mosip.vciclient.constants.CredentialFormat.LDP_VC,
            doctype = null,
            claims = null,
            preAuthorizedCode = "sample-pre-auth-code",
            tokenEndpoint = mockWebServer.url("/token").toString()
        )
    }

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
        service = PreAuthTokenService()
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `should return TokenResponse when server returns 200 OK`() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(sampleTokenJson)
        )

        val response = service.exchangePreAuthCodeForToken(createValidIssuerMetaData(), null)

        assertEquals("sample-token", response.accessToken)
        assertEquals("sample-cnonce", response.cNonce)
    }

    @Test
    fun `should throw DownloadFailedException when pre-authorized code is missing`() {
        val invalidMetaData = createValidIssuerMetaData().copy(preAuthorizedCode = null)

        assertThrows(DownloadFailedException::class.java) {
            service.exchangePreAuthCodeForToken(invalidMetaData, null)
        }
    }

    @Test
    fun `should throw DownloadFailedException when token endpoint is missing`() {
        val invalidMetaData = createValidIssuerMetaData().copy(tokenEndpoint = null)

        assertThrows(DownloadFailedException::class.java) {
            service.exchangePreAuthCodeForToken(invalidMetaData, null)
        }
    }

    @Test
    fun `should throw DownloadFailedException when response is empty`() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
        )

        assertThrows(DownloadFailedException::class.java) {
            service.exchangePreAuthCodeForToken(createValidIssuerMetaData(), null)
        }
    }

    @Test
    fun `should throw InvalidAccessTokenException when access_token is missing`() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"token_type":"Bearer"}""")
        )

        assertThrows(InvalidAccessTokenException::class.java) {
            service.exchangePreAuthCodeForToken(createValidIssuerMetaData(), null)
        }
    }

    @Test
    fun `should throw NetworkRequestFailedException on IO error`() {
        mockWebServer.shutdown()

        assertThrows(NetworkRequestFailedException::class.java) {
            service.exchangePreAuthCodeForToken(createValidIssuerMetaData(), null)
        }
    }
}
