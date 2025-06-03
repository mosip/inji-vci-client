package io.mosip.vciclient.issuerMetadata

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.exception.IssuerMetadataFetchException
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class IssuerMetadataServiceTest {

    private val issuerUrl = "https://mock.issuer"
    private val wellKnownUrl = "$issuerUrl/.well-known/openid-credential-issuer"

    @Before
    fun setup() {
        mockkObject(NetworkManager)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should parse ldp_vc metadata successfully`() = runBlocking {
        mockJsonResponse(LDP_VC_JSON)

        val result = IssuerMetadataService().fetch(issuerUrl, "UniversityDegreeCredential")
        val resolved = result.issuerMetadata

        assertEquals(CredentialFormat.LDP_VC, resolved.credentialFormat)
        assertEquals("https://mock.issuer", resolved.credentialAudience)
        assertEquals(listOf("VerifiableCredential"), resolved.credentialType)
        assertEquals("openid degree", resolved.scope)
        assertTrue(resolved.authorizationServers!!.contains("https://auth"))
        assertTrue(resolved.context!!.contains("https://www.w3.org/2018/credentials/v1"))
    }

    @Test
    fun `should parse mso_mdoc metadata successfully`() = runBlocking {
        mockJsonResponse(MSO_MDOC_JSON)

        val result = IssuerMetadataService().fetch(issuerUrl, "DrivingLicense")
        val resolved = result.issuerMetadata

        assertEquals(CredentialFormat.MSO_MDOC, resolved.credentialFormat)
        assertEquals("org.iso.18013.5.1.mDL", resolved.doctype)
        assertTrue(resolved.claims!!.containsKey("name"))
    }

    @Test
    fun `should throw if response is empty`() = runBlocking {
        mockJsonResponse("")

        val ex = assertThrows<IssuerMetadataFetchException> {
            IssuerMetadataService().fetch(issuerUrl, "Invalid")
        }
        assertTrue(ex.message.contains("response is empty"))
    }

    @Test
    fun `should throw if credential_configurations_supported is missing`() = runBlocking {
        mockJsonResponse("""{ "credential_issuer": "https://mock.issuer" }""")

        val ex = assertThrows<IssuerMetadataFetchException> {
            IssuerMetadataService().fetch(issuerUrl, "MissingConfig")
        }
        assertTrue(ex.message.contains("credential_configurations_supported"))
    }

    @Test
    fun `should throw if credential configuration id does not exist`() = runBlocking {
        mockJsonResponse(LDP_VC_JSON) // only contains "UniversityDegreeCredential"

        val ex = assertThrows<IssuerMetadataFetchException> {
            IssuerMetadataService().fetch(issuerUrl, "NonExistentCredential")
        }
        assertTrue(ex.message.contains("Credential configuration not found"))
    }

    @Test
    fun `should throw if format is unknown`() = runBlocking {
        mockJsonResponse(INVALID_FORMAT_JSON)

        val ex = assertThrows<IssuerMetadataFetchException> {
            IssuerMetadataService().fetch(issuerUrl, "TestCredential")
        }
        assertTrue(ex.message.contains("Unsupported or missing credential format"))
    }


    private fun mockJsonResponse(body: String) {
        every {
            NetworkManager.sendRequest(wellKnownUrl, any(), any())
        } returns NetworkResponse(body,null)
    }

    companion object {
        const val LDP_VC_JSON = """
        {
          "credential_issuer": "https://mock.issuer",
          "credential_endpoint": "https://mock.issuer/endpoint",
          "authorization_servers": ["https://auth"],
          "credential_configurations_supported": {
            "UniversityDegreeCredential": {
              "format": "ldp_vc",
              "scope": "degree",
              "credential_definition": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"]
              }
            }
          }
        }
        """

        const val MSO_MDOC_JSON = """
        {
          "credential_issuer": "https://mock.issuer",
          "credential_endpoint": "https://mock.issuer/endpoint",
          "authorization_servers": ["https://auth"],
          "credential_configurations_supported": {
            "DrivingLicense": {
              "format": "mso_mdoc",
              "doctype": "org.iso.18013.5.1.mDL",
              "claims": {
                "name": { "mandatory": true }
              }
            }
          }
        }
        """

        const val INVALID_FORMAT_JSON = """
        {
          "credential_issuer": "https://mock.issuer",
          "credential_endpoint": "https://mock.issuer/endpoint",
          "authorization_servers": ["https://auth"],
          "credential_configurations_supported": {
            "TestCredential": {
              "format": "unsupported_format"
            }
          }
        }
        """
    }
}
