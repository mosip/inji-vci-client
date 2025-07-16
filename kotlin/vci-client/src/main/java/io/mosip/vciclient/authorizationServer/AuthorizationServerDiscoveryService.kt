package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.AuthorizationServerDiscoveryException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

private const val OAUTH_WELL_KNOWN_URI_SUFFIX = "/.well-known/oauth-authorization-server"
private const val OPENID_WELL_KNOWN_URI_SUFFIX = "/.well-known/openid-configuration"

class AuthorizationServerDiscoveryService {
    private val logger = Logger.getLogger(javaClass.simpleName)

    /**
     * Discovers the authorization server metadata by querying the well-known endpoints.
     * Some authorization servers will choose to support "openid-configuration" well-known suffix while some will choose to go with default "oauth-authorization-server" suffix.
     * reference - https://datatracker.ietf.org/doc/html/rfc8414#section-3
     */
    suspend fun discover(baseUrl: String): AuthorizationServerMetadata = withContext(Dispatchers.IO) {
        val oauthUrl = "$baseUrl$OAUTH_WELL_KNOWN_URI_SUFFIX"
        val openidUrl = "$baseUrl$OPENID_WELL_KNOWN_URI_SUFFIX"

        try {
            val oauthResponse = NetworkManager.sendRequest(
                url = oauthUrl,
                method = HttpMethod.GET,
                timeoutMillis = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS
            )
            if (oauthResponse.body.isNotBlank()) {
                JsonUtils.deserialize(oauthResponse.body, AuthorizationServerMetadata::class.java)
                    ?.let { return@withContext it }
            }
        } catch (e: Exception) {
            logger.warning("OAuth discovery failed, trying OpenID discovery: ${e.message}")
        }

        try {
            val openidResponse = NetworkManager.sendRequest(
                url = openidUrl,
                method = HttpMethod.GET,
                timeoutMillis = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS
            )
            if (openidResponse.body.isNotBlank()) {
                JsonUtils.deserialize(openidResponse.body, AuthorizationServerMetadata::class.java)
                    ?.let { return@withContext it }
            }
        } catch (e: Exception) {
            logger.warning("OpenID discovery also failed: ${e.message}")
        }

        throw AuthorizationServerDiscoveryException("Failed to discover authorization server metadata at both endpoints")
    }
}
