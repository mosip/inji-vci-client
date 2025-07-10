package io.mosip.vciclient.authorizationServer

import org.junit.Assert.assertEquals
import org.junit.Test

class AuthorizationUrlBuilderTest {

    @Test
    fun `build should return exact expected URL using form-url-encoding`() {
        val actual = AuthorizationUrlBuilder.build(
            baseUrl = "https://example.com/auth",
            clientId = "myClientId",
            redirectUri = "https://myapp.com/callback",
            scope = "openid profile email",
            state = "abc123",
            codeChallenge = "xyzChallenge",
            nonce = "randomNonce"
        )

        val expected = "https://example.com/auth" +
                "?client_id=myClientId" +
                "&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback" +
                "&response_type=code" +
                "&scope=openid+profile+email" +
                "&state=abc123" +
                "&code_challenge=xyzChallenge" +
                "&code_challenge_method=S256" +
                "&nonce=randomNonce"

        assertEquals(expected, actual)
    }
}
