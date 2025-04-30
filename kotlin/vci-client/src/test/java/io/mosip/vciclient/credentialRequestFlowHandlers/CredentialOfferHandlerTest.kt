package io.mosip.vciclient.credentialRequestFlowHandlers

import android.content.Context
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferGrants
import io.mosip.vciclient.credentialOffer.CredentialOfferService
import io.mosip.vciclient.credentialOffer.PreAuthorizedCodeGrant
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthFlow.PreAuthFlowService
import io.mosip.vciclient.trustedIssuersManager.TrustedIssuerRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class CredentialOfferHandlerTest {

    private val mockCredentialResponse = mockk<CredentialResponse>()
    private val mockCredentialOffer = mockk<CredentialOffer>()
    private val mockIssuerMetadataResult = mockk<IssuerMetadataResult>()
    private val mockClientMetadata = mockk<ClientMetadata>()

    private lateinit var txCode: suspend (String?, String?, Int?) -> String
    private lateinit var getProofJwt: suspend (String, String?, Map<String, *>?, String?) -> String
    private lateinit var getAuthCode: suspend (String) -> String
    private lateinit var onCheckIssuerTrust: suspend (Map<String, Any>) -> Boolean
    private lateinit var trustedIssuerRegistry: TrustedIssuerRegistry


    @Before
    fun setup() {
        mockkConstructor(CredentialOfferService::class)
        mockkConstructor(IssuerMetadataService::class)
        mockkConstructor(PreAuthFlowService::class)
        mockkConstructor(AuthorizationCodeFlowService::class)
        trustedIssuerRegistry=mockk()
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns mockCredentialOffer
        coEvery {
            anyConstructed<IssuerMetadataService>().fetch(
                any(),
                any()
            )
        } returns mockIssuerMetadataResult
        every { mockIssuerMetadataResult.issuerMetadata } returns mockk(relaxed = true)
        every { mockIssuerMetadataResult.raw } returns mapOf("some" to "metadata")
        coEvery { trustedIssuerRegistry.isTrusted(any()) } returns false
        coEvery { trustedIssuerRegistry.markTrusted(any()) } just Runs

        txCode = object : suspend (String?, String?, Int?) -> String {
            override suspend fun invoke(
                p1: String?,p2:String?,p3:Int?
            ): String = "mock-auth-code"
        }
        getAuthCode = object : suspend (String) -> String {
            override suspend fun invoke(
                authEndpoint: String,
            ): String = "mock-auth-code"
        }

        getProofJwt = object : suspend (String, String?, Map<String, *>?, String?) -> String {
            override suspend fun invoke(
                accessToken: String,
                cNonce: String?,
                issuerMetadata: Map<String, *>?,
                credentialCOnfigurationId: String?,
            ): String = "mock.jwt.proof"
        }
        onCheckIssuerTrust = mockk()
        coEvery { onCheckIssuerTrust.invoke(any()) } returns true
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential for pre-authorized flow`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthorizedCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthFlowService>().requestCredentials(
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns mockCredentialResponse

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        val result = CredentialOfferHandler().downloadCredentials(
            credentialOffer = "some-offer",
            clientMetadata = mockClientMetadata,
            txCode = txCode,
            proofJwt = getProofJwt,
            authCode = getAuthCode,
            onCheckIssuerTrust,
            trustedIssuerRegistry = trustedIssuerRegistry
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw if flow type is not supported`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(null, null)
        )

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<OfferFetchFailedException> {
            CredentialOfferHandler().downloadCredentials(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                txCode = txCode,
                proofJwt = getProofJwt,
                authCode = getAuthCode,
                onCheckIssuerTrust = onCheckIssuerTrust,
                trustedIssuerRegistry =trustedIssuerRegistry
            )
        }
    }

    @Test
    fun `should throw if no credential is returned`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthorizedCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthFlowService>().requestCredentials(
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns null

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<OfferFetchFailedException> {
            CredentialOfferHandler().downloadCredentials(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                txCode = txCode,
                proofJwt = getProofJwt,
                authCode = getAuthCode,
                onCheckIssuerTrust=onCheckIssuerTrust,
                trustedIssuerRegistry = trustedIssuerRegistry
            )
        }
    }

    @Test
    fun `should throw if user does not give trust consent for untrusted issuer`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthorizedCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery { onCheckIssuerTrust.invoke(any()) } returns false

        coEvery {
            anyConstructed<CredentialOfferService>().fetchCredentialOffer(any())
        } returns offer

        assertThrows<OfferFetchFailedException> {
            CredentialOfferHandler().downloadCredentials(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                txCode = txCode,
                proofJwt = getProofJwt,
                authCode = getAuthCode,
                onCheckIssuerTrust = onCheckIssuerTrust,
                trustedIssuerRegistry = trustedIssuerRegistry
            )
        }
    }


}
