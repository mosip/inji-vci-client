package io.mosip.vciclient.proof.jwt

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import io.mosip.vciclient.common.DateProvider
import io.mosip.vciclient.common.Encoder
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.JWTProofType
import io.mosip.vciclient.constants.ProofType
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.proof.Proof
import kotlin.math.floor

private const val TOKEN_EXPIRATION_PERIOD_IN_MILLISECONDS = 18000

class JWTProof : Proof {
    override val proofType: String = ProofType.JWT.value
    var jwt: String = ""

    constructor()

    constructor(jwt: String) {
        this.jwt = jwt
    }
    
    override fun generate(
        publicKeyPem: String,
        accessToken: String,
        issuerMetadata: IssuerMetadata,
        signer: (ByteArray) -> ByteArray,
        algorithm: JWTProofType.Algorithms,
    ): Proof {
        val header: String =
            JWTProofHeader(JWTProofType.Algorithms.RS256.name, publicKeyPem).build()

        val payload: String = buildPayload(accessToken, issuerMetadata)
        this.jwt = generateJWT(header, payload, signer)
        return this
    }

    private fun buildPayload(accessToken: String, issuerMetadata: IssuerMetadata): String {
        try {
            val decodedAccessToken: JWT = JWTParser.parse(accessToken)
            val jwtClaimsSet: JWTClaimsSet = decodedAccessToken.jwtClaimsSet
            val issuanceTime: Long =
                floor((DateProvider.getCurrentTime() / 1000).toDouble()).toLong()

            return JWTProofPayload(
                jwtClaimsSet.getClaim("client_id").toString(),
                jwtClaimsSet.getClaim("c_nonce").toString(),
                issuerMetadata.credentialIssuer,
                issuanceTime,
                issuanceTime + TOKEN_EXPIRATION_PERIOD_IN_MILLISECONDS
            )
                .build()
        } catch (exception: Exception) {
            throw InvalidAccessTokenException(exception.message!!)
        }
    }

    private fun generateJWT(
        header: String,
        payload: String,
        signer: (ByteArray) -> ByteArray,
    ): String {
        val encoder = Encoder()
        val encodedHeader: String =
            encoder.encodeToBase64UrlFormat(header).replace('+', '-').replace('/', '_')
        val encodedPayload: String = encoder.encodeToBase64UrlFormat(payload)

        val contentBytes =
            constructContentByteArray(
                Util.toByteArray(encodedHeader),
                Util.toByteArray(encodedPayload)
            )

        val signature: String =
            encoder.encodeToBase64UrlFormat(signer(contentBytes))

        return "$encodedHeader.$encodedPayload.$signature"
    }

    private fun constructContentByteArray(
        headerByteArray: ByteArray,
        payloadByteArray: ByteArray,
    ): ByteArray {
        val contentBytes = ByteArray(headerByteArray.size + 1 + payloadByteArray.size)
        System.arraycopy(headerByteArray, 0, contentBytes, 0, headerByteArray.size)
        contentBytes[headerByteArray.size] = '.'.code.toByte()
        System.arraycopy(
            payloadByteArray,
            0,
            contentBytes,
            headerByteArray.size + 1,
            payloadByteArray.size
        )
        return contentBytes
    }
}