package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.exception.OfferFetchFailedException
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class CredentialOfferValidatorTest {

    private val validOffer = CredentialOffer(
        credentialIssuer = "https://issuer.example.com",
        credentialConfigurationIds = listOf("UniversityDegreeCredential"),
        grants = CredentialOfferGrants(
            preAuthorizedGrant = PreAuthorizedCodeGrant("abc123", TxCode("Enter code", 6)),
            authorizationCodeGrant = null
        )
    )

    @Test
    fun `should pass validation for valid credential offer`() {
        CredentialOfferValidator.validate(validOffer)
    }

    @Test
    fun `should throw when credential_issuer is blank`() {
        val offer = validOffer.copy(credentialIssuer = "")
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("credential_issuer must not be blank"))
    }

    @Test
    fun `should throw when credential_issuer is not https`() {
        val offer = validOffer.copy(credentialIssuer = "http://issuer.example.com")
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("credential_issuer must use HTTPS"))
    }

    @Test
    fun `should throw when credential_configuration_ids is empty`() {
        val offer = validOffer.copy(credentialConfigurationIds = emptyList())
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("credential_configuration_ids must not be empty"))
    }

    @Test
    fun `should throw when credential_configuration_ids contains blank`() {
        val offer = validOffer.copy(credentialConfigurationIds = listOf(" "))
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("credential_configuration_ids must not contain blank values"))
    }

    @Test
    fun `should pass when grants is null`() {
        val offer = validOffer.copy(grants = null)
        CredentialOfferValidator.validate(offer)
    }

    @Test
    fun `should throw when grants has no supported types`() {
        val offer = validOffer.copy(grants = CredentialOfferGrants(null, null))
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("grants must contain at least one supported grant type"))
    }

    @Test
    fun `should throw when pre-authorized_code is blank`() {
        val offer = validOffer.copy(
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthorizedCodeGrant("", null),
                authorizationCodeGrant = null
            )
        )
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("pre-authorized_code must not be blank"))
    }

    @Test
    fun `should throw when txCode length is zero`() {
        val offer = validOffer.copy(
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthorizedCodeGrant("abc123", TxCode("Enter code", 0)),
                authorizationCodeGrant = null
            )
        )
        val ex = assertThrows<OfferFetchFailedException> {
            CredentialOfferValidator.validate(offer)
        }
        assert(ex.message.contains("tx_code.length must be greater than 0"))
    }
}
