package io.mosip.vciclient.token

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mosip.vciclient.constants.GrantType
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class TokenServiceTest {
    private val tokenService = TokenService()
    private val tokenEndpoint = "https://token.endpoint"
    private val mockTokenResponse = TokenResponse(
        accessToken = "test_token",
        tokenType = "Bearer",
        expiresIn = 3600,
        cNonce = "test_nonce"
    )

    @Test
    fun `getAccessToken should create correct request for pre-authorized flow`() = runBlocking {
        // Arrange
        val getTokenResponse = mockk<suspend (TokenRequest) -> TokenResponse>()
        coEvery { getTokenResponse(any()) } returns mockTokenResponse

        // Act
        val result = tokenService.getAccessToken(
            getTokenResponse = getTokenResponse,
            tokenEndpoint = tokenEndpoint,
            preAuthCode = "pre-auth-code",
            txCode = "tx-code"
        )

        // Assert
        assertEquals(mockTokenResponse, result)
        coVerify {
            getTokenResponse(match { request ->
                request.grantType == GrantType.PRE_AUTHORIZED &&
                        request.tokenEndpoint == tokenEndpoint &&
                        request.preAuthCode == "pre-auth-code" &&
                        request.txCode == "tx-code" &&
                        request.authCode == null &&
                        request.clientId == null &&
                        request.redirectUri == null &&
                        request.codeVerifier == null
            })
        }
    }

    @Test
    fun `getAccessToken should create correct request for authorization code flow`() = runBlocking {
        // Arrange
        val getTokenResponse = mockk<suspend (TokenRequest) -> TokenResponse>()
        coEvery { getTokenResponse(any()) } returns mockTokenResponse

        // Act
        val result = tokenService.getAccessToken(
            getTokenResponse = getTokenResponse,
            tokenEndpoint = tokenEndpoint,
            authCode = "auth-code",
            clientId = "client-id",
            redirectUri = "redirect-uri",
            codeVerifier = "code-verifier"
        )

        // Assert
        assertEquals(mockTokenResponse, result)
        coVerify {
            getTokenResponse(match { request ->
                request.grantType == GrantType.AUTHORIZATION_CODE &&
                        request.tokenEndpoint == tokenEndpoint &&
                        request.authCode == "auth-code" &&
                        request.clientId == "client-id" &&
                        request.redirectUri == "redirect-uri" &&
                        request.codeVerifier == "code-verifier" &&
                        request.preAuthCode == null &&
                        request.txCode == null
            })
        }
    }

    @Test
    fun `getAccessToken should handle errors from token response`() = runBlocking {
        // Arrange
        val exception = RuntimeException("Test error")
        val getTokenResponse = mockk<suspend (TokenRequest) -> TokenResponse>()
        coEvery { getTokenResponse(any()) } throws exception

        val ex = assertThrows<RuntimeException> {
            tokenService.getAccessToken(
                getTokenResponse = getTokenResponse,
                tokenEndpoint = tokenEndpoint,
                preAuthCode = "pre-auth-code"
            )
        }
        assertEquals(exception.message, ex.message)
    }
}
