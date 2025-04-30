package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mockk.*
import io.mosip.vciclient.common.JsonUtils
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class CredentialOfferServiceTest {

    private val embeddedOfferJson = """{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["UniversityDegreeCredential"]}"""
    private val encodedOffer = java.net.URLEncoder.encode(embeddedOfferJson, "UTF-8")
    private val wrappedOffer = "openid-credential-offer://?credential_offer=$encodedOffer"
    private val uriOfferUrl = "https://example.com/offer.json"
    private val wrappedUri = "openid-credential-offer://?credential_offer_uri=${java.net.URLEncoder.encode(uriOfferUrl, "UTF-8")}"

    private val mockCredentialOffer = CredentialOffer(
        credentialIssuer = "https://issuer.example.com",
        credentialConfigurationIds = listOf("UniversityDegreeCredential"),
        grants = null
    )

    @Before
    fun setup() {
        mockkObject(NetworkManager)
        mockkObject(JsonUtils)
        mockkObject(CredentialOfferValidator)
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should parse credential_offer param and return valid offer`() = runBlocking {
        every { JsonUtils.deserialize(any(), CredentialOffer::class.java) } returns mockCredentialOffer
        every { CredentialOfferValidator.validate(any()) } just Runs

        val result = CredentialOfferService().fetchCredentialOffer(wrappedOffer)
        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should fetch and parse credential_offer_uri`() = runBlocking {
        every {
            NetworkManager.sendRequest(uriOfferUrl, HttpMethod.GET, any(), any())
        } returns io.mosip.vciclient.networkManager.NetworkResponse(embeddedOfferJson,null)

        every { JsonUtils.deserialize(embeddedOfferJson, CredentialOffer::class.java) } returns mockCredentialOffer
        every { CredentialOfferValidator.validate(any()) } just Runs

        val result = CredentialOfferService().fetchCredentialOffer(wrappedUri)
        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should throw when URI has no parameters`() = runBlocking {
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferService().fetchCredentialOffer("openid-credential-offer://?")
        }
        assert(ex.message.contains("URL not valid"))
    }

    @Test
    fun `should throw when URI lacks required keys`() = runBlocking {
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferService().fetchCredentialOffer("openid-credential-offer://?foo=bar")
        }
        assert(ex.message.contains("must contain"))
    }

    @Test
    fun `should throw when embedded offer is invalid JSON`() {
        every {
            JsonUtils.deserialize(any(), CredentialOffer::class.java)
        } returns null

        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferService().handleByValueOffer(encodedOffer)
        }
        assert(ex.message.contains("Invalid credential offer JSON"))
    }

    @Test
    fun `should throw when URI response is empty`() = runBlocking {
        every {
            NetworkManager.sendRequest(uriOfferUrl, HttpMethod.GET, any(), any())
        } returns io.mosip.vciclient.networkManager.NetworkResponse("",null)

        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferService().handleByReferenceOffer(uriOfferUrl)
        }
        assert(ex.message.contains("Empty response"))
    }

    @Test
    fun `should ignore extra query params`() = runBlocking {
        every { JsonUtils.deserialize(any(), CredentialOffer::class.java) } returns mockCredentialOffer
        every { CredentialOfferValidator.validate(any()) } just Runs

        val result = CredentialOfferService().fetchCredentialOffer("$wrappedOffer&extra=value")
        assertEquals("https://issuer.example.com", result.credentialIssuer)
    }

    @Test
    fun `should throw when url decoding fails`() = runBlocking {
        val malformed = "openid-credential-offer://?credential_offer=%"

        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferService().fetchCredentialOffer(malformed)
        }
        assert(ex.message.isNotBlank())
    }
}