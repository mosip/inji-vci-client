package io.mosip.vciclient.proof

import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.constants.JWTProofType
import io.mosip.vciclient.issuerMetadata.IssuerMetadata

interface Proof {
    @get:SerializedName("proof_type")
    val proofType: String
    fun generate(
        publicKeyPem: String,
        accessToken: String,
        issuerMetadata: IssuerMetadata,
        signer: (ByteArray) -> ByteArray,
        algorithm: JWTProofType.Algorithms,
    ): Proof
}