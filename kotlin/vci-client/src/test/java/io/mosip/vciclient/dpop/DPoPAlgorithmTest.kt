package io.mosip.vciclient.dpop

import io.mosip.vciclient.exception.DPoPException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.test.assertFailsWith

class DPoPAlgorithmTest {

    @Test
    fun `defaults to ES256 when list is null or empty`() {
        assertEquals(DPoPAlgorithm.ES256, DPoPAlgorithm.select(null))
        assertEquals(DPoPAlgorithm.ES256, DPoPAlgorithm.select(emptyList()))
    }

    // Priority group 1 – ed (EdDSA)
    @Test
    fun `prefers EdDSA over all other algorithms`() {
        assertEquals(
            DPoPAlgorithm.EDDSA,
            DPoPAlgorithm.select(listOf("RS256", "ES256", "ES256K", "EdDSA"))
        )
    }

    // Priority group 2 – eck1 (ES256K / secp256k1)
    @Test
    fun `prefers ES256K over ecr1 variants and RSA`() {
        assertEquals(DPoPAlgorithm.ES256K, DPoPAlgorithm.select(listOf("ES512", "ES256K", "ES256")))
    }

    // Priority group 3 – ecr1 (ES256 / secp256r1)
    @Test
    fun `prefers ES256 over larger EC curves and RSA`() {
        assertEquals(DPoPAlgorithm.ES256, DPoPAlgorithm.select(listOf("ES512", "ES384", "ES256")))
    }

    // Priority group 4 – edc other EC r1 variants (ES384 before ES512)
    @Test
    fun `prefers ES384 over ES512 and RSA`() {
        assertEquals(DPoPAlgorithm.ES384, DPoPAlgorithm.select(listOf("RS256", "ES512", "ES384")))
    }

    @Test
    fun `prefers ES512 over RSA`() {
        assertEquals(DPoPAlgorithm.ES512, DPoPAlgorithm.select(listOf("RS256", "ES512")))
    }

    // Priority group 5 – rsa (RS256); last resort
    @Test
    fun `selects RS256 when it is the only recognised algorithm`() {
        assertEquals(DPoPAlgorithm.RS256, DPoPAlgorithm.select(listOf("RS256", "PS512")))
    }

    @Test
    fun `throws when AS advertises only unsupported algorithms`() {
        val exception = assertFailsWith<DPoPException> {
            DPoPAlgorithm.select(listOf("PS256", "HS256"))
        }
        assertEquals("VCI-013", exception.code)
        assertTrue(exception.message.contains("No supported DPoP algorithm found"))
    }

    @Test
    fun `every supported algorithm generates a key and signer`() {
        DPoPAlgorithm.values().forEach { algorithm ->
            val key = algorithm.generateKey()
            assertEquals(false, key.toPublicJWK().isPrivate)
            // signer construction must not throw for the generated key
            algorithm.signer(key)
        }
    }
}
