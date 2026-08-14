package io.mosip.vciclient.dpop

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.DPoPException
import java.net.URI
import java.security.MessageDigest
import java.util.Date
import java.util.UUID

/**
 * Owns the DPoP mechanism for a single issuance flow as described in the DPoP ADR (RFC 9449).
 *
 * A fresh ephemeral key pair is generated in memory for the flow and reused to sign every
 * proof - the `dpop_jkt` in the authorization URL, the token-endpoint proof, and the
 * credential-endpoint proof. The key never leaves the library and is never persisted.
 */
class DPoPManager {
    private class Session(val key: JWK, val algorithm: DPoPAlgorithm, val tokenEndpoint: String)

    private var session: Session? = null

    private var issuerNonce: String? = null

    val isInitialized: Boolean
        get() = session != null

    fun initialize(tokenEndpoint: String, authorizationServerSupportedAlgorithms: List<String>?) {
        if (session != null) return
        try {
            val algorithm = DPoPAlgorithm.select(authorizationServerSupportedAlgorithms)
            session = Session(algorithm.generateKey(), algorithm, normalizeHtu(tokenEndpoint))
        } catch (e: DPoPException) {
            throw e
        } catch (e: Exception) {
            throw DPoPException(
                "Unexpected error while initializing the DPoP session: ${e.message}",
                cause = e
            )
        }
    }

    fun reset() {
        session = null
        issuerNonce = null
    }

    fun updateNonce(nonce: String?) {
        if (!nonce.isNullOrBlank()) issuerNonce = nonce
    }

    fun jwkThumbprint(): String {
        try {
            return requireSession().key.toPublicJWK().computeThumbprint().toString()
        } catch (e: DPoPException) {
            throw e
        } catch (e: Exception) {
            throw DPoPException(
                "Unexpected error while computing the DPoP JWK thumbprint: ${e.message}",
                cause = e
            )
        }
    }

    fun generateTokenProof(nonce: String? = null): String {
        try {
            val activeSession = requireSession()
            return buildProof(activeSession, activeSession.tokenEndpoint, nonce, accessToken = null)
        } catch (e: DPoPException) {
            throw e
        } catch (e: Exception) {
            throw DPoPException(
                "Unexpected error while generating the token DPoP proof: ${e.message}",
                cause = e
            )
        }
    }

    fun generateCredentialProof(
        credentialEndpoint: String,
        accessToken: String,
        nonce: String? = null,
    ): String {
        try {
            val activeSession = requireSession()
            updateNonce(nonce)
            return buildProof(
                activeSession,
                normalizeHtu(credentialEndpoint),
                issuerNonce,
                accessToken
            )
        } catch (e: DPoPException) {
            throw e
        } catch (e: Exception) {
            throw DPoPException(
                "Unexpected error while generating the credential DPoP proof: ${e.message}",
                cause = e
            )
        }
    }

    private fun buildProof(
        activeSession: Session,
        htu: String,
        nonce: String?,
        accessToken: String?,
    ): String {
        val issuedAt = Date()
        val claims = JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .claim("htm", Constants.HTTP_METHOD_POST)
            .claim("htu", htu)
            .issueTime(issuedAt)
            .expirationTime(Date(issuedAt.time + Constants.DPOP_PROOF_LIFETIME_SECONDS * 1000))
            .apply {
                if (nonce != null) claim("nonce", nonce)
                if (accessToken != null) claim("ath", accessTokenHash(accessToken))
            }
            .build()

        val header = JWSHeader.Builder(activeSession.algorithm.jwsAlgorithm)
            .type(JOSEObjectType(Constants.DPOP_JWT_TYPE))
            .jwk(activeSession.key.toPublicJWK())
            .build()

        return SignedJWT(header, claims)
            .apply { sign(activeSession.algorithm.signer(activeSession.key)) }
            .serialize()
    }

    private fun accessTokenHash(accessToken: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(accessToken.toByteArray(Charsets.US_ASCII))
        return Base64URL.encode(digest).toString()
    }

    private fun requireSession(): Session = session
        ?: throw DPoPException("DPoP session is not initialized for the current flow")

    private fun normalizeHtu(endpoint: String): String {
        val uri = URI(endpoint).normalize()
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        val port = when {
            uri.port == -1 -> -1
            scheme == "https" && uri.port == 443 -> -1
            scheme == "http" && uri.port == 80 -> -1
            else -> uri.port
        }
        return URI(scheme, null, host, port, uri.path.ifEmpty { "/" }, null, null).toString()
    }
}
