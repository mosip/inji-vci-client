package io.mosip.vciclient.dpop

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.mosip.vciclient.exception.DPoPException
import java.util.UUID

private const val RSA_KEY_SIZE = 2048

internal enum class DPoPAlgorithm(val algorithmName: String, val jwsAlgorithm: JWSAlgorithm) {
    EDDSA("EdDSA", JWSAlgorithm.EdDSA) {
        override fun generateKey(): JWK =
            OctetKeyPairGenerator(Curve.Ed25519).keyID(generateKeyId()).generate()

        override fun signer(key: JWK): JWSSigner = Ed25519Signer(key as OctetKeyPair)
    },
    ES256K("ES256K", JWSAlgorithm.ES256K) {
        override fun generateKey(): JWK =
            ECKeyGenerator(Curve.SECP256K1)
                .provider(BouncyCastleProviderSingleton.getInstance())
                .keyID(generateKeyId())
                .generate()

        override fun signer(key: JWK): JWSSigner =
            ECDSASigner(key as ECKey).apply {
                jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
            }
    },
    ES256("ES256", JWSAlgorithm.ES256) {
        override fun generateKey(): JWK = generateEcKey(Curve.P_256)
        override fun signer(key: JWK): JWSSigner = ECDSASigner(key as ECKey)
    },
    ES384("ES384", JWSAlgorithm.ES384) {
        override fun generateKey(): JWK = generateEcKey(Curve.P_384)
        override fun signer(key: JWK): JWSSigner = ECDSASigner(key as ECKey)
    },
    ES512("ES512", JWSAlgorithm.ES512) {
        override fun generateKey(): JWK = generateEcKey(Curve.P_521)
        override fun signer(key: JWK): JWSSigner = ECDSASigner(key as ECKey)
    },
    RS256("RS256", JWSAlgorithm.RS256) {
        override fun generateKey(): JWK =
            RSAKeyGenerator(RSA_KEY_SIZE).keyID(generateKeyId()).generate()

        override fun signer(key: JWK): JWSSigner = RSASSASigner(key as RSAKey)
    };

    abstract fun generateKey(): JWK
    abstract fun signer(key: JWK): JWSSigner

    companion object {
        /**
         * Preference order for ephemeral DPoP key selection:
         *  1. EdDSA  (ed)           – Edwards-curve; smallest signatures, modern
         *  2. ES256K (eck1)         – ECDSA secp256k1; widely deployed
         *  3. ES256  (ecr1)         – ECDSA secp256r1 (P-256); default fallback
         *  4. ES384, ES512          – Other EC r1 variants (P-384, P-521)
         *  5. RS256  (rsa)          – RSA; last resort, large key/signature size
         */
        private val preferenceOrder = listOf(EDDSA, ES256K, ES256, ES384, ES512, RS256)
        private val DEFAULT = ES256

        fun select(authorizationServerSupported: List<String>?): DPoPAlgorithm {
            if (authorizationServerSupported.isNullOrEmpty()) return DEFAULT
            return preferenceOrder.firstOrNull { it.algorithmName in authorizationServerSupported }
                ?: throw DPoPException(
                    "No supported DPoP algorithm found. AS supports: $authorizationServerSupported, " +
                    "client supports: ${preferenceOrder.map { it.algorithmName }}"
                )
        }

        private fun generateKeyId(): String = UUID.randomUUID().toString()

        private fun generateEcKey(curve: Curve): JWK =
            ECKeyGenerator(curve).keyID(generateKeyId()).generate()
    }
}
