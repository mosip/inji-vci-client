package io.mosip.vciclient.dpop

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import io.mosip.vciclient.exception.DPoPException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import java.security.MessageDigest

class DPoPManagerTest {

    private fun initializedManager(
        tokenEndpoint: String = "https://as.example.com/token",
        algorithms: List<String>? = listOf("ES256"),
    ): DPoPManager = DPoPManager().apply { initialize(tokenEndpoint, algorithms) }

    @Test
    fun `is not initialized before initialize is called`() {
        assertFalse(DPoPManager().isInitialized)
    }

    @Test
    fun `is initialized after initialize is called`() {
        assertTrue(initializedManager().isInitialized)
    }

    @Test
    fun `token proof has dpop type header public jwk and required claims`() {
        val proof = initializedManager().generateTokenProof()
        val jwt = SignedJWT.parse(proof)

        assertEquals("dpop+jwt", jwt.header.type.toString())
        assertEquals("ES256", jwt.header.algorithm.name)

        val jwk = jwt.header.jwk
        assertNotNull(jwk)
        assertFalse("Public JWK must not contain the private key", jwk.isPrivate)

        val claims = jwt.jwtClaimsSet
        assertNotNull(claims.getStringClaim("jti"))
        assertEquals("POST", claims.getStringClaim("htm"))
        assertEquals("https://as.example.com/token", claims.getStringClaim("htu"))
        assertNotNull(claims.issueTime)
        assertNotNull(claims.expirationTime)
    }

    @Test
    fun `token proof is verifiable with the embedded public key`() {
        val proof = initializedManager().generateTokenProof()
        val jwt = SignedJWT.parse(proof)
        val publicKey = ECKey.parse(jwt.header.jwk.toJSONString())
        assertTrue(jwt.verify(ECDSAVerifier(publicKey)))
    }

    @Test
    fun `token proof has no ath claim`() {
        val jwt = SignedJWT.parse(initializedManager().generateTokenProof())
        assertNull(jwt.jwtClaimsSet.getStringClaim("ath"))
    }

    @Test
    fun `token proof omits nonce when not supplied and includes it when supplied`() {
        val manager = initializedManager()
        assertNull(SignedJWT.parse(manager.generateTokenProof()).jwtClaimsSet.getStringClaim("nonce"))
        assertEquals(
            "nonce-123",
            SignedJWT.parse(manager.generateTokenProof("nonce-123")).jwtClaimsSet.getStringClaim("nonce")
        )
    }

    @Test
    fun `credential proof includes ath as base64url sha256 of access token`() {
        val accessToken = "an-access-token"
        val proof = initializedManager().generateCredentialProof(
            credentialEndpoint = "https://issuer.example.com/credential",
            accessToken = accessToken
        )
        val claims = SignedJWT.parse(proof).jwtClaimsSet

        val expectedAth = Base64URL.encode(
            MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.US_ASCII))
        ).toString()

        assertEquals(expectedAth, claims.getStringClaim("ath"))
        assertEquals("https://issuer.example.com/credential", claims.getStringClaim("htu"))
    }

    @Test
    fun `credential proof uses stored issuer nonce when none is supplied`() {
        val manager = initializedManager()
        manager.updateNonce("issuer-nonce")

        val claims = SignedJWT.parse(
            manager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet

        assertEquals("issuer-nonce", claims.getStringClaim("nonce"))
    }

    @Test
    fun `credential proof supplied nonce overrides and updates the stored nonce`() {
        val manager = initializedManager()
        manager.updateNonce("old-nonce")

        val first = SignedJWT.parse(
            manager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token",
                nonce = "new-nonce"
            )
        ).jwtClaimsSet
        assertEquals("new-nonce", first.getStringClaim("nonce"))

        val second = SignedJWT.parse(
            manager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet
        assertEquals("new-nonce", second.getStringClaim("nonce"))
    }

    @Test
    fun `updateNonce ignores blank values`() {
        val manager = initializedManager()
        manager.updateNonce("issuer-nonce")
        manager.updateNonce(null)
        manager.updateNonce(" ")

        val claims = SignedJWT.parse(
            manager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet
        assertEquals("issuer-nonce", claims.getStringClaim("nonce"))
    }

    @Test
    fun `reset clears the stored issuer nonce`() {
        val manager = initializedManager()
        manager.updateNonce("issuer-nonce")
        manager.reset()
        manager.initialize("https://as.example.com/token", listOf("ES256"))

        val claims = SignedJWT.parse(
            manager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet
        assertNull(claims.getStringClaim("nonce"))
    }

    @Test
    fun `htu strips query string and fragment`() {
        val manager = DPoPManager().apply {
            initialize("https://as.example.com/token?foo=bar#frag", listOf("ES256"))
        }
        val claims = SignedJWT.parse(manager.generateTokenProof()).jwtClaimsSet
        assertEquals("https://as.example.com/token", claims.getStringClaim("htu"))
    }

    @Test
    fun `thumbprint matches the embedded public jwk thumbprint`() {
        val manager = initializedManager()
        val proof = SignedJWT.parse(manager.generateTokenProof())
        val embeddedThumbprint = proof.header.jwk.computeThumbprint().toString()
        assertEquals(embeddedThumbprint, manager.jwkThumbprint())
    }

    @Test
    fun `every proof has a unique jti`() {
        val manager = initializedManager()
        val first = SignedJWT.parse(manager.generateTokenProof()).jwtClaimsSet.getStringClaim("jti")
        val second = SignedJWT.parse(manager.generateTokenProof()).jwtClaimsSet.getStringClaim("jti")
        assertFalse(first == second)
    }

    @Test
    fun `produces a verifiable proof for every supported algorithm`() {
        listOf("EdDSA", "ES256K", "ES256", "ES384", "ES512", "RS256").forEach { alg ->
            val jwt = SignedJWT.parse(initializedManager(algorithms = listOf(alg)).generateTokenProof())
            assertEquals(alg, jwt.header.algorithm.name)
            val jwk = jwt.header.jwk
            assertFalse("Public JWK must not contain the private key for $alg", jwk.isPrivate)

            val verifier: JWSVerifier = when (jwk) {
                is OctetKeyPair -> Ed25519Verifier(jwk)
                is RSAKey -> RSASSAVerifier(jwk)
                is ECKey -> ECDSAVerifier(jwk).apply {
                    jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                }
                else -> throw IllegalStateException("Unexpected JWK type for $alg")
            }
            assertTrue("Proof for $alg must verify", jwt.verify(verifier))
        }
    }

    @Test
    fun `selects es384 when only es384 is advertised`() {
        val jwt = SignedJWT.parse(initializedManager(algorithms = listOf("ES384")).generateTokenProof())
        assertEquals("ES384", jwt.header.algorithm.name)
    }

    @Test
    fun `falls back to es256 when authorization server omits the algorithm list`() {
        val jwt = SignedJWT.parse(initializedManager(algorithms = null).generateTokenProof())
        assertEquals("ES256", jwt.header.algorithm.name)
    }

    @Test
    fun `generate proof throws when session is not initialized`() {
        val exception = assertThrows<DPoPException> { DPoPManager().generateTokenProof() }
        assertEquals("VCI-013", exception.code)
    }

    @Test
    fun `jwk thumbprint throws when session is not initialized`() {
        val exception = assertThrows<DPoPException> { DPoPManager().jwkThumbprint() }
        assertEquals("VCI-013", exception.code)
    }

    @Test
    fun `initialize wraps a non dpop failure as a dpop exception`() {
        val exception = assertThrows<DPoPException> {
            DPoPManager().initialize("ht tp://as.example.com/token", listOf("ES256"))
        }
        assertEquals("VCI-013", exception.code)
        assertTrue(exception.message.contains("Unexpected error while initializing the DPoP session"))
    }

    @Test
    fun `reset clears the session`() {
        val manager = initializedManager()
        manager.reset()
        assertFalse(manager.isInitialized)
    }

    @Test
    fun `initialize is idempotent within a flow`() {
        val manager = initializedManager()
        val thumbprintBefore = manager.jwkThumbprint()
        manager.initialize("https://other.example.com/token", listOf("ES384"))
        assertEquals(thumbprintBefore, manager.jwkThumbprint())
    }
}
