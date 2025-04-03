package io.mosip.vciclient.credentialoffer

import io.mosip.vciclient.credentialOffer.CredentialOfferService
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.OfferFetchFailedException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.net.URLEncoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows

class CredentialOfferServiceTest {

    private lateinit var server: MockWebServer
    private lateinit var service: CredentialOfferService

    private val validCredentialOfferJson = """
        {
          "credential_issuer": "https://issuer.example.com",
          "credential_configuration_ids": ["UniversityDegreeCredential"]
        }
    """.trimIndent()

    private val invalidCredentialOfferJson = """
        {
          "credential_issuer": "https://issuer.example.com",
          "credential_configuration_ids": [""]
        }
    """.trimIndent()

    @Before
    fun setup() {
        server = MockWebServer()
        server.start()
        service = CredentialOfferService()
    }

    @After
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun `should parse valid credential offer by value`() {
        val encoded = URLEncoder.encode(validCredentialOfferJson, "UTF-8")
        val result = service.handleByValueOffer(encoded)
        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should throw OfferFetchFailedException on invalid JSON by value`() {
        val encoded = URLEncoder.encode(invalidCredentialOfferJson, "UTF-8")
        assertThrows(OfferFetchFailedException::class.java) {
            service.handleByValueOffer(encoded)
        }
    }

    @Test
    fun `should fetch and parse valid credential offer by reference`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(validCredentialOfferJson))

        val url = server.url("/offer").toString()
        val result = service.handleByReferenceOffer(url)
        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should throw on 404 response by reference`() {
        server.enqueue(MockResponse().setResponseCode(404).setBody("Not found"))

        val url = server.url("/offer").toString()
        assertThrows(NetworkRequestFailedException::class.java) {
            service.handleByReferenceOffer(url)
        }
    }

    @Test
    fun `should throw on empty response body`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(""))

        val url = server.url("/empty").toString()
        assertThrows(OfferFetchFailedException::class.java) {
            service.handleByReferenceOffer(url)
        }
    }

    @Test
    fun `should throw on invalid JSON from reference`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(invalidCredentialOfferJson))

        val url = server.url("/bad-json").toString()
        assertThrows(OfferFetchFailedException::class.java) {
            service.handleByReferenceOffer(url)
        }
    }
}
