package io.mosip.vciclient.proof.jwt


import android.os.Build
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.vciclient.common.BuildConfig
import io.mosip.vciclient.common.DateProvider
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.JWTProofType
import io.mosip.vciclient.constants.ProofType
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.exception.InvalidAccessTokenException
import org.junit.Assert
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.text.ParseException

class JWTProofTest {
    private val publicKeyPEM = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAi/X/H2tFMb5y5S1OG/OWLRacXo4Qos7Md0N9szlfL6vqS98DPXVY
H45q/mZKqcyJVSRSEv9fdJkhoRUi3VM60tJs+by/XnqYjs6FNtWGDoUsR52Qjj4z
NlmPBbw7eBjug3IwPmlKGntkiyJFhle+3g/voBY+mOOAZaCkG1i8/JnkLkDyr0kY
aoOfZ5gO4Q5+gT7CdN7rXzd786DZ8tsVX3VPWL+QjJ1158EcsYa3EEi3DtfCBSKI
QEjSdPAJ40rf1byPwWNi2npLIXwI0vzt8OyMn3xiYYwdq7/Oqq/6ZfStGN1uQb2i
1WVFDQks6c0vD2tdMyYMFsLBhIZxQ8F2EmYtnTawTkJknpt3vIDWOfkNNU9UtEe5
cZU0g6JZfy4R98LUnNDEtANC+dgYDj/iJ361mbGT/eIQIqUSCnLuRrk2hUbSzok6
ErI/92KoXPlyUfqRlv9YpOsIfCtetPHpKCu0hkZAU7iroTi0gDL1Ts/cpNfaAlbB
gyjrHerxHhqy8v0ZofjNatOeepnqbvOuaGjOS4sTpyvOSmADUPlCGom6jsHhLAB5
9jQ2d3jODcHPdnccAJ5IweTZ69OB/+JcpERjecmtOT0Ac9HlpxulL5tgzxFLLRqO
ptxWSQnlPIXZbrtSYFkPQOHN8Ba0o1b4iNK3AX43WFy8srpOkEPqGJcCAwEAAQ==
-----END RSA PUBLIC KEY-----"""
    private val accessToken =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
    private val invalidAccessToken = "invalid-access-token"
    private val issuerMetadata: IssuerMetadata = IssuerMetadata(
        "/https://domain.net",
        "/https://domain.net/credential",
        credentialType = listOf("VerifiableCredential"),
        credentialFormat = CredentialFormat.LDP_VC
    )
    private val currentTimeMillis = 1618373400000L

    private fun signer(input: ByteArray): ByteArray {
        return byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04)
    }

    @Before
    fun setUp() {
        mockkObject(BuildConfig)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O

        mockkObject(DateProvider)
        every { DateProvider.getCurrentTime() } returns currentTimeMillis

        mockkStatic(JWTParser::class)
        every { JWTParser.parse(accessToken).jwtClaimsSet } returns JWTClaimsSet.parse(
            mutableMapOf(
                "client_id" to "ClientId123-90",
                "c_nonce" to "pqwwegrwgerdvwjhSDV",
            ) as Map<String, Any>?
        )
    }

    @Test
    fun `should generate JWT for the given payload and header with the signer function passed`() {
        val generatedProofJWT: Proof = JWTProof().generate(
            publicKeyPEM, accessToken, issuerMetadata, ::signer, JWTProofType.Algorithms.RS256
        )

        assertEquals(
            ProofType.JWT.value,
            generatedProofJWT.proofType
        )
        assertEquals(
            "ewogICAgImFsZyI6ICJSUzI1NiIsCiAgICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0IiwKICAgICJqd2siOiB7CiAgICAgICAgImt0eSI6ICJSU0EiLAogICAgICAgICJlIjogIkFRQUIiLAogICAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgICAiYWxnIjogIlJTMjU2IiwKICAgICAgICAibiI6ICJpX1hfSDJ0Rk1iNXk1UzFPR19PV0xSYWNYbzRRb3M3TWQwTjlzemxmTDZ2cVM5OERQWFZZSDQ1cV9tWktxY3lKVlNSU0V2OWZkSmtob1JVaTNWTTYwdEpzLWJ5X1hucVlqczZGTnRXR0RvVXNSNTJRamo0ek5sbVBCYnc3ZUJqdWczSXdQbWxLR250a2l5SkZobGUtM2dfdm9CWS1tT09BWmFDa0cxaThfSm5rTGtEeXIwa1lhb09mWjVnTzRRNS1nVDdDZE43clh6ZDc4NkRaOHRzVlgzVlBXTC1RakoxMTU4RWNzWWEzRUVpM0R0ZkNCU0tJUUVqU2RQQUo0MHJmMWJ5UHdXTmkybnBMSVh3STB2enQ4T3lNbjN4aVlZd2RxN19PcXFfNlpmU3RHTjF1UWIyaTFXVkZEUWtzNmMwdkQydGRNeVlNRnNMQmhJWnhROEYyRW1ZdG5UYXdUa0prbnB0M3ZJRFdPZmtOTlU5VXRFZTVjWlUwZzZKWmZ5NFI5OExVbk5ERXRBTkMtZGdZRGpfaUozNjFtYkdUX2VJUUlxVVNDbkx1UnJrMmhVYlN6b2s2RXJJXzkyS29YUGx5VWZxUmx2OVlwT3NJZkN0ZXRQSHBLQ3UwaGtaQVU3aXJvVGkwZ0RMMVRzX2NwTmZhQWxiQmd5anJIZXJ4SGhxeTh2MFpvZmpOYXRPZWVwbnFidk91YUdqT1M0c1RweXZPU21BRFVQbENHb202anNIaExBQjU5alEyZDNqT0RjSFBkbmNjQUo1SXdlVFo2OU9CXy1KY3BFUmplY210T1QwQWM5SGxweHVsTDV0Z3p4RkxMUnFPcHR4V1NRbmxQSVhaYnJ0U1lGa1BRT0hOOEJhMG8xYjRpTkszQVg0M1dGeThzcnBPa0VQcUdKYyIKICAgIH0KfQ.ewogICAgImlzcyI6ICJDbGllbnRJZDEyMy05MCIsCiAgICAiYXVkIjogIi9odHRwczovL2RvbWFpbi5uZXQiLAogICAgImV4cCI6IDE2MTgzOTE0MDAsCiAgICAibm9uY2UiOiAicHF3d2VncndnZXJkdndqaFNEViIsCiAgICAiaWF0IjogMTYxODM3MzQwMAp9.AAECAwQ",
            (generatedProofJWT as JWTProof).jwt
        )
    }

    @Test
    fun `should throw InvalidAccessTokenException if the accessToken is invalid`() {
        every { JWTParser.parse(invalidAccessToken) } throws ParseException(
            "Invalid JWT serialization: Missing dot delimiter(s)",
            2
        )


        val invalidAccessTokenException = Assert.assertThrows(
            InvalidAccessTokenException::class.java,
        ) {
            JWTProof().generate(
                publicKeyPEM,
                invalidAccessToken,
                issuerMetadata,
                ::signer,
                JWTProofType.Algorithms.RS256
            )
        }

        assertEquals(
            "Access token is invalid - Invalid JWT serialization: Missing dot delimiter(s)",
            invalidAccessTokenException.message
        )
    }
}