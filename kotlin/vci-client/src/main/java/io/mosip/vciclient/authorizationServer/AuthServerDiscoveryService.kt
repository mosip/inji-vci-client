package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.AuthServerDiscoveryException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

class AuthServerDiscoveryService {
    private val logger = Logger.getLogger(javaClass.simpleName)
    suspend fun discover(baseUrl: String): AuthServerMetadata = withContext(Dispatchers.IO) {
        val oauthUrl = "$baseUrl/.well-known/oauth-authorization-server"
        val openidUrl = "$baseUrl/.well-known/openid-configuration"

        try {
            val oauthResponse = NetworkManager.sendRequest(
                url = oauthUrl,
                method = HttpMethod.GET,
                timeoutMillis = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS
            )
            if (oauthResponse.body.isNotBlank()) {
                JsonUtils.deserialize(oauthResponse.body, AuthServerMetadata::class.java)
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
                JsonUtils.deserialize(openidResponse.body, AuthServerMetadata::class.java)
                    ?.let { return@withContext it }
            }
        } catch (e: Exception) {
            logger.warning("OpenID discovery also failed: ${e.message}")
        }

        throw AuthServerDiscoveryException("Failed to discover authorization server metadata at both endpoints")
    }
}
