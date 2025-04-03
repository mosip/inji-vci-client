package io.mosip.vciclient

import PreAuthTokenService
import com.google.gson.Gson
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import kotlinx.coroutines.runBlocking
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.JWTProofType
import io.mosip.vciclient.constants.ProofType
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferService
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.text.ParseException


private const val mockCredentialOfferData =
    "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D"

class VCIClientTest {
    private var credentialEndpoint = "/https://domain.net/credential"
    private var credentialAudience = "/https://domain.net"
    private val accessToken =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
    private val downloadTimeout = 10000
    private lateinit var mockWebServer: MockWebServer
    private val mockCredentialResponse = """{
    "format": "ldp_vc",
    "credential": {
      "issuanceDate": "2024-04-14T16:04:35.304Z",
      "credentialSubject": {
        "face": "data:image/jpeg;base64,/9j/goKCyuig",
        "dateOfBirth": "2000/01/01",
        "id": "did:jwk:eyJr80435=",
        "UIN": "9012378996",
        "email": "mockuser@gmail.com"
      },
      "id": "https://domain.net/credentials/12345-87435",
      "proof": {
        "type": "RsaSignature2018",
        "created": "2024-04-14T16:04:35Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://domain.net/.well-known/public-key.json",
        "jws": "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"
      },
      "type": [
        "VerifiableCredential"
      ],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://domain.net/.well-known/context.json",
        {
          "sec": "https://w3id.org/security#"
        }
      ],
      "issuer": "https://domain.net/.well-known/issuer.json"
    }
  }"""
    private val mockCredentialRequestSuccessResponse: MockResponse =
        MockResponse().setBody(
            mockCredentialResponse
        ).addHeader("Content-Type", "application/json")
            .setResponseCode(200)
    private val publicKey = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E
lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM
CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR
baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz
GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU
MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK
Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE
AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS
XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd
BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU
IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==
-----END RSA PUBLIC KEY-----"""

    private fun signer(input: ByteArray): ByteArray {
        return byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04)
    }

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        mockkConstructor(JWTProof::class)
        val jwtProof = mockk<JWTProof>()
        every { jwtProof.proofType } returns ProofType.JWT.value
        every { jwtProof.jwt } returns "headerEncoded.payloadEncoded.signature"
        every {
            anyConstructed<JWTProof>().generate(
                any(),
                any(),
                any(),
                any(),
                JWTProofType.Algorithms.RS256
            )
        } returns jwtProof

        mockkStatic(JWTParser::class)
        every { JWTParser.parse(accessToken).jwtClaimsSet } returns JWTClaimsSet.parse(
            mutableMapOf(
                "client_id" to "ZYTEWR6734_P3-90",
                "c_nonce" to "pqwwegrwgerdvwjhSDV",
            ) as Map<String, Any>?
        )
    }

    @After
    fun tearDown() {
        clearAllMocks()
        mockWebServer.shutdown()
    }


    @Test
    fun `should make api call to credential endpoint with the right params in case of ldpVc`() {
        mockWebServer.enqueue(mockCredentialRequestSuccessResponse)

        VCIClient("test-vci-client").requestCredential(
            IssuerMetaData(
                credentialAudience,
                mockWebServer.url(credentialEndpoint).toString(),
                downloadTimeout,
                credentialType = arrayOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ),
            JWTProof("headerEncoded.payloadEncoded.signature"),
            accessToken
        )
        val request: RecordedRequest = mockWebServer.takeRequest()

        assertEquals(
            "POST $credentialEndpoint HTTP/1.1",
            request.requestLine
        )
        assertEquals("application/json; charset=utf-8", request.getHeader("Content-Type"))
        assertEquals(
            "{\"format\":\"ldp_vc\",\"credential_definition\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\"]},\"proof\":{\"proof_type\":\"jwt\",\"jwt\":\"headerEncoded.payloadEncoded.signature\"}}",
            request.body.readUtf8()
        )
    }

    @Test
    fun `should return credential when valid access token, public key PEM is passed and credential endpoint api is success in case of ldpVc`() {
        mockWebServer.enqueue(mockCredentialRequestSuccessResponse)

        val credentialResponse = VCIClient("test-vci-client").requestCredential(
            IssuerMetaData(
                credentialAudience,
                mockWebServer.url(credentialEndpoint).toString(),
                downloadTimeout,
                credentialType = arrayOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ),
            JWTProof("headerEncoded.payloadEncoded.signature"),
            accessToken
        )

        assertEquals(
            Gson().fromJson(mockCredentialResponse, CredentialResponse::class.java),
            credentialResponse
        )
    }

    @Test
    fun `should return null when credential endpoint responded with empty body`() {
        mockWebServer.enqueue(mockCredentialRequestSuccessResponse.setBody(""))

        val credentialResponse = VCIClient("test-vci-client").requestCredential(
            IssuerMetaData(
                credentialAudience,
                mockWebServer.url(credentialEndpoint).toString(),
                downloadTimeout,
                credentialType = arrayOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ),
            JWTProof("headerEncoded.payloadEncoded.signature"),
            accessToken
        )

        assertNull(credentialResponse)
    }

    @Test
    fun `should throw download failure exception when credential endpoint api response is not 200`() {
        val mockCredentialRequestFailureResponse: MockResponse = MockResponse().setResponseCode(500)
        mockWebServer.enqueue(mockCredentialRequestFailureResponse)

        val thrown: DownloadFailedException = assertThrows(
            DownloadFailedException::class.java,
        ) {
            VCIClient("test-vci-client").requestCredential(
                IssuerMetaData(
                    credentialAudience,
                    mockWebServer.url(credentialEndpoint).toString(),
                    10000, credentialType = arrayOf("VerifiableCredential"),
                    credentialFormat = CredentialFormat.LDP_VC
                ), JWTProof("headerEncoded.payloadEncoded.signature"), accessToken
            )
        }

        assertEquals("Download failed due to Server Error", thrown.message)
    }

    @Test
    fun `should throw timeout exception when credential endpoint api call takes more time than the passed timeout`() {
        val issuerWithLessTimeout =
            IssuerMetaData(
                credentialAudience,
                mockWebServer.url(credentialEndpoint).toString(),
                1,
                credentialType = arrayOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            )

        val networkRequestTimeoutException = assertThrows(
            NetworkRequestTimeoutException::class.java,
        ) {
            VCIClient("test-vci-client").requestCredential(
                issuerWithLessTimeout,
                JWTProof("headerEncoded.payloadEncoded.signature"),
                accessToken
            )
        }

        assertEquals(
            "Download failed due to request timeout",
            networkRequestTimeoutException.message
        )
    }

    @Test
    @Ignore("accessToken is not decrypted as JWTProof is given from the consumer")
    fun `should throw invalid access token exception when invalid access token is passed`() {
        val invalidAccessToken = "invalid-access-token"
        clearAllMocks()
        mockkStatic(JWTParser::class)
        every { JWTParser.parse(invalidAccessToken) } throws ParseException(
            "Invalid JWT serialization: Missing dot delimiter(s)",
            2
        )

        val invalidAccessTokenException = assertThrows(
            InvalidAccessTokenException::class.java,
        ) {
            VCIClient("test-vci-client").requestCredential(
                IssuerMetaData(
                    credentialAudience,
                    mockWebServer.url(credentialEndpoint).toString(),
                    downloadTimeout, credentialType = arrayOf("VerifiableCredential"),
                    credentialFormat = CredentialFormat.LDP_VC
                ),
                JWTProof("headerEncoded.payloadEncoded.signature"),
                invalidAccessToken
            )
        }

        assertEquals(
            "Access token is invalid - Invalid JWT serialization: Missing dot delimiter(s)",
            invalidAccessTokenException.message
        )
    }

    @Test
    @Ignore("JWTProof is not generated as JWTProof is given from the consumer")
    fun `should throw download failed exception with message when download fails`() {
        mockkConstructor(JWTProof::class)
        every {
            anyConstructed<JWTProof>().generate(
                any(),
                any(),
                any(),
                any(),
                JWTProofType.Algorithms.RS256
            )
        } throws Exception(
            "Unknown exception"
        )

        val downloadFailedException = assertThrows(
            DownloadFailedException::class.java,
        ) {
            VCIClient("test-vci-client").requestCredential(
                IssuerMetaData(
                    credentialAudience,
                    mockWebServer.url(credentialEndpoint).toString(),
                    downloadTimeout, credentialType = arrayOf("VerifiableCredential"),
                    credentialFormat = CredentialFormat.LDP_VC
                ),
                JWTProof("headerEncoded.payloadEncoded.signature"),
                accessToken
            )
        }
        assertEquals(
            "Download failed due to Unknown exception",
            downloadFailedException.message
        )
    }

    @Test
    fun `should fetch credential-offer from embedded offer`() {
        val offerJson = """
            {
              "credential_issuer": "https://issuer.example.com",
              "credential_configuration_ids": ["UniversityDegreeCredential"]
            }
        """.trimIndent()

        mockkConstructor(CredentialOfferService::class)

        every { anyConstructed<CredentialOfferService>().handleByValueOffer(any()) } returns JsonUtils.deserialize(
            offerJson,
            CredentialOffer::class.java
        )!!

        val result =
            VCIClient("test").fetchCredentialOfferIssuer(
                mockCredentialOfferData
            )

        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should fetch credential-offer from uri offer`() {
        val offerJson = """
            {
              "credential_issuer": "https://issuer.example.com",
              "credential_configuration_ids": ["UniversityDegreeCredential"]
            }
        """.trimIndent()

        mockkConstructor(CredentialOfferService::class)

        every { anyConstructed<CredentialOfferService>().handleByReferenceOffer(any()) } returns JsonUtils.deserialize(
            offerJson,
            CredentialOffer::class.java
        )!!

        val result =
            VCIClient("test").fetchCredentialOfferIssuer("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver%2Eexample%2Ecom%2Fcredential-offer.json")

        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should throw OfferFetchFailedException if neither credential_offer nor credential_offer_uri present`() {

        assertThrows(OfferFetchFailedException::class.java) {
            VCIClient("test").fetchCredentialOfferIssuer("openid-credential-offer://?invalid_param=xyz")
        }
    }

    @Test
    fun `should return credential when pre-authorized flow succeeds`() = runBlocking {
        mockWebServer.enqueue(mockCredentialRequestSuccessResponse)

        val preAuthToken = TokenResponse("mockAccessToken", tokenType = "jwt", cNonce = "mockCNonce")
        mockkConstructor(PreAuthTokenService::class)
        every { anyConstructed<PreAuthTokenService>().exchangePreAuthCodeForToken(any(), any()) } returns preAuthToken

        val result = VCIClient("test").requestCredentialByPreAuthFlow(
            IssuerMetaData(
                credentialAudience,
                mockWebServer.url(credentialEndpoint).toString(),
                downloadTimeout,
                credentialType = arrayOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ),
            txCode = "123456",
            getProofJwt =  { accessToken, cNonce ->
                assertEquals("mockAccessToken", accessToken)
                assertEquals("mockCNonce", cNonce)
                "header.payload.signature"
            }
        )

        assertEquals(
            Gson().fromJson(mockCredentialResponse, CredentialResponse::class.java),
            result
        )
    }
}
