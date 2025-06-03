package io.mosip.vciclient.token

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class TokenServiceTest {

    private val tokenEndpoint = "https://mock.token.endpoint"
    private val invalidResponse = """{ "tokenType": "Bearer" }"""
    private val validTokenResponse = """
        {
            "access_token": "valid_token",
            "token_type": "Bearer",
            "c_nonce": "sample_nonce",
            "exprires_in": 3600
        }
    """.trimIndent()

    @Before
    fun setup() {
        mockkObject(NetworkManager)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should return token when pre-auth flow succeeds`() = runBlocking {
        every {
            NetworkManager.sendRequest(
                url = tokenEndpoint,
                method = HttpMethod.POST,
                headers = any(),
                bodyParams = match { it["pre-authorized_code"] == "abc123" },
                timeoutMillis = any()
            )
        } returns io.mosip.vciclient.networkManager.NetworkResponse(validTokenResponse, null)

        val result = TokenService().getAccessToken(
            tokenEndpoint = tokenEndpoint, preAuthCode = "abc123"
        )

        assertEquals("valid_token", result.accessToken)
    }

    @Test
    fun `should return token when authorization code flow succeeds`() = runBlocking {
        every {
            NetworkManager.sendRequest(
                url = tokenEndpoint,
                method = HttpMethod.POST,
                headers = any(),
                bodyParams = match { it["code"] == "auth-code-123" },
                timeoutMillis = any()
            )
        } returns io.mosip.vciclient.networkManager.NetworkResponse(validTokenResponse, null)

        val result = TokenService().getAccessToken(
            tokenEndpoint = tokenEndpoint,
            authCode = "auth-code-123",
            clientId = "client-id",
            redirectUri = "app://redirect",
            codeVerifier = "verifier123"
        )

        assertEquals("valid_token", result.accessToken)
    }

    @Test
    fun `should throw when preAuthCode is missing`() {
        val exception = assertThrows<DownloadFailedException> {
            runBlocking {
                TokenService().getAccessToken(
                    tokenEndpoint = tokenEndpoint, preAuthCode = ""
                )
            }
        }

        assertTrue(exception.message.contains("Pre-authorized code is missing."))
    }

    @Test
    fun `should throw when authCode is missing`() {
        val exception = assertThrows<DownloadFailedException> {
            runBlocking {
                TokenService().getAccessToken(
                    tokenEndpoint = tokenEndpoint, authCode = ""
                )
            }
        }
        assertTrue(exception.message.contains("Authorization code is missing."))
    }

    @Test
    fun `should throw when response body is empty`() {
        every {
            NetworkManager.sendRequest(any(), any(), any(), any(), any())
        } returns io.mosip.vciclient.networkManager.NetworkResponse("", null)

        val exception = assertThrows<DownloadFailedException> {
            runBlocking {
                TokenService().getAccessToken(
                    tokenEndpoint = tokenEndpoint, preAuthCode = "abc123"
                )
            }
        }

        assertTrue(exception.message.contains("Token response body is empty"))
    }

    @Test
    fun `should throw when access token is missing in response`() {

        every {
            NetworkManager.sendRequest(any(), any(), any(), any(), any())
        } returns io.mosip.vciclient.networkManager.NetworkResponse(invalidResponse, null)

        val exception = assertThrows<InvalidAccessTokenException> {
            runBlocking {
                TokenService().getAccessToken(
                    tokenEndpoint = tokenEndpoint, preAuthCode = "abc123"
                )
            }
        }

        assertTrue(exception.message.contains("Access token missing in token response"))
    }
}
