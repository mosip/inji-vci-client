package io.mosip.vciclient.proof.jwt

import android.util.Log
import io.fusionauth.jwks.domain.JSONWebKey
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.JWTProofType
import io.mosip.vciclient.exception.InvalidPublicKeyException
import org.json.JSONObject


private const val ALGORITHM = "alg"

class JWTProofHeader(algorithm: String, publicKeyPem: String) {

    private val header = JSONObject(
        (mutableMapOf(
            ALGORITHM to algorithm,
            "typ" to JWTProofType.TYPE.value,
            "jwk" to pemToJWK(publicKeyPem),
        ) as Map<*, *>?)!!
    )

    private fun pemToJWK(publicKeyPem: String): JSONObject {
        val publicKeyJWK: JSONWebKey
        try {
            publicKeyJWK = JSONWebKey.build(publicKeyPem)
        } catch (exception: Exception) {
            throw InvalidPublicKeyException(exception.toString())
        }
        val jwkJson = JSONObject(publicKeyJWK.toJSON())
        jwkJson.put(ALGORITHM, JWTProofType.Algorithms.RS256)
        return jwkJson
    }

    fun build(): String = header.toString(4)
}