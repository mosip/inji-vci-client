package io.mosip.vciclient.issuerMetadata

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.exception.IssuerMetadataFetchException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Suppress("UNCHECKED_CAST")
class IssuerMetadataService {
    private val timeoutMillis: Long = 10000
    private var cachedIssuerMetadataResult: IssuerMetadataResult? = null

    suspend fun fetchIssuerMetadataResult(
        issuerUri: String,
        credentialConfigurationId: String
    ): IssuerMetadataResult = withContext(Dispatchers.IO) {
        // Check cache first
        cachedIssuerMetadataResult?.takeIf { it.issuerUri == issuerUri }?.let {
            return@withContext it
        }

        val raw = fetchAndParseIssuerMetadata(issuerUri)
        val resolved = resolveMetadata(
            credentialConfigurationId = credentialConfigurationId,
            rawIssuerMetadata = raw
        )

        val result = IssuerMetadataResult(
            issuerMetadata = resolved,
            raw = raw,
            issuerUri = issuerUri
        )
        // Update cache
        cachedIssuerMetadataResult = result
        return@withContext result
    }

    fun fetchAndParseIssuerMetadata(credentialIssuerUri: String): Map<String, Any> {
        val wellKnownUrl = "$credentialIssuerUri/.well-known/openid-credential-issuer"

        try {
            val response = NetworkManager.sendRequest(
                url = wellKnownUrl,
                method = HttpMethod.GET,
                timeoutMillis = timeoutMillis
            )

            val body = response.body
            if (body.isBlank()) {
                throw IssuerMetadataFetchException("Issuer metadata response is empty.")
            }

            return JsonUtils.toMap(body)
        } catch (e: IssuerMetadataFetchException) {
            throw e
        } catch (e: Exception) {
            throw IssuerMetadataFetchException("Failed to fetch issuer metadata: ${e.message}")
        }
    }

    private fun resolveMetadata(
        credentialConfigurationId: String,
        rawIssuerMetadata: Map<String, Any>
    ): IssuerMetadata {
        val credentialConfigurationsSupported = rawIssuerMetadata["credential_configurations_supported"] as? Map<*, *>
            ?: throw IssuerMetadataFetchException("Missing credential_configurations_supported")

        val credentialType = credentialConfigurationsSupported[credentialConfigurationId] as? Map<*, *>
            ?: throw IssuerMetadataFetchException("Credential configuration not found: $credentialConfigurationId")

        val credentialEndpoint = rawIssuerMetadata["credential_endpoint"] as? String
            ?: throw IssuerMetadataFetchException("Missing credential_endpoint")

        val credentialIssuer = rawIssuerMetadata["credential_issuer"] as? String
            ?: throw IssuerMetadataFetchException("Missing credential_issuer")

        val format = credentialType["format"] as? String

        return when (format) {
            CredentialFormat.MSO_MDOC.value -> {
                val doctype = credentialType["doctype"] as? String
                    ?: throw IssuerMetadataFetchException("Missing doctype")
                val claims = credentialType["claims"] as? Map<String, Any>

                IssuerMetadata(
                    credentialIssuer = credentialIssuer,
                    credentialEndpoint = credentialEndpoint,
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    doctype = doctype,
                    claims = claims,
                    authorizationServers = rawIssuerMetadata["authorization_servers"] as? List<String>
                )
            }

            CredentialFormat.LDP_VC.value -> {
                val credentialDefinition = credentialType["credential_definition"] as? Map<*, *> ?: emptyMap<String, Any>()
                val types = credentialDefinition["type"] as? List<String>
                val context = credentialDefinition["@context"] as? List<String>
                val scope = credentialType["scope"] as? String ?: ""

                IssuerMetadata(
                    credentialIssuer = credentialIssuer,
                    credentialEndpoint = credentialEndpoint,
                    credentialType = types,
                    context = context,
                    credentialFormat = CredentialFormat.LDP_VC,
                    authorizationServers = rawIssuerMetadata["authorization_servers"] as? List<String>,
                    scope = "openid $scope".trim()
                )
            }

            else -> throw IssuerMetadataFetchException("Unsupported or missing credential format in configuration")
        }
    }
}