package io.mosip.vciclient.dpop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WwwAuthenticateChallengeTest {

    @Test
    fun `parses a dpop use_dpop_nonce challenge`() {
        val challenge = WwwAuthenticateChallenge.parse("""DPoP error="use_dpop_nonce", error_description="nonce required"""")
        assertTrue(challenge.isDpop)
        assertFalse(challenge.isBearer)
        assertEquals("use_dpop_nonce", challenge.error)
    }

    @Test
    fun `parses a bearer only challenge`() {
        val challenge = WwwAuthenticateChallenge.parse("""Bearer realm="issuer", error="invalid_token"""")
        assertFalse(challenge.isDpop)
        assertTrue(challenge.isBearer)
        assertEquals("invalid_token", challenge.error)
    }

    @Test
    fun `detects dpop when present among multiple schemes`() {
        val challenge = WwwAuthenticateChallenge.parse("""Bearer realm="r", DPoP algs="ES256"""")
        assertTrue(challenge.isDpop)
        assertTrue(challenge.isBearer)
    }

    @Test
    fun `returns empty challenge for null or blank header`() {
        listOf(null, "", "   ").forEach {
            val challenge = WwwAuthenticateChallenge.parse(it)
            assertFalse(challenge.isDpop)
            assertFalse(challenge.isBearer)
            assertNull(challenge.error)
        }
    }

    @Test
    fun `isBearer is false when header contains unrecognised scheme only`() {
        val challenge = WwwAuthenticateChallenge.parse("""NTLM realm="corp"""")
        assertFalse(challenge.isDpop)
        assertFalse(challenge.isBearer)
    }

    @Test
    fun `attributes the error to the dpop challenge when both schemes carry an error`() {
        val challenge = WwwAuthenticateChallenge.parse(
            """Bearer error="invalid_token", DPoP error="use_dpop_nonce""""
        )
        assertTrue(challenge.isDpop)
        assertTrue(challenge.isBearer)
        assertEquals("use_dpop_nonce", challenge.error)
    }
}
