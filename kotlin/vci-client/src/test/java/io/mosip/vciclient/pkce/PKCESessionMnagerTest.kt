package io.mosip.vciclient.pkce

import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class PKCESessionManagerTest {

    @Test
    fun `createSession should return non-empty verifier, challenge, state, and nonce`() {
        val session = PKCESessionManager().createSession()

        assertTrue("Verifier should not be blank", session.codeVerifier.isNotBlank())
        assertTrue("Challenge should not be blank", session.codeChallenge.isNotBlank())
        assertTrue("State should not be blank", session.state.isNotBlank())
        assertTrue("Nonce should not be blank", session.nonce.isNotBlank())
    }

    @Test
    fun `codeChallenge should be base64url(SHA256(codeVerifier))`() {
        val session = PKCESessionManager().createSession()

        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(session.codeVerifier.toByteArray(Charsets.UTF_8))

        val expectedChallenge = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(sha256)

        assertEquals("Challenge must match SHA256 hash of verifier", expectedChallenge, session.codeChallenge)
    }
}
