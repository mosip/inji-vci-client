import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.*
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.token.TokenResponse

class PreAuthTokenService {

    @Throws(
        DownloadFailedException::class,
        InvalidAccessTokenException::class,
        NetworkRequestTimeoutException::class,
        NetworkRequestFailedException::class
    )
    fun exchangePreAuthCodeForToken(
        issuerMetaData: IssuerMetaData,
        txCode: String?,
    ): TokenResponse {
        val preAuthCode = issuerMetaData.preAuthorizedCode
        val tokenEndpoint = issuerMetaData.tokenEndpoint

        if (preAuthCode.isNullOrBlank()) {
            throw DownloadFailedException("Pre-authorized code is missing.")
        }

        if (tokenEndpoint.isNullOrBlank()) {
            throw DownloadFailedException("Token endpoint is missing.")
        }

        val bodyParams = mutableMapOf(
            "grant_type" to "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code" to preAuthCode
        )

        txCode?.let { bodyParams["tx_code"] = it }

        val headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        val response = NetworkManager.sendRequest(
            url = tokenEndpoint,
            method = HttpMethod.POST,
            headers = headers,
            bodyParams = bodyParams,
            timeoutMillis = issuerMetaData.downloadTimeoutInMilliSeconds.toLong()
        )

        return parseAccessTokenResponse(response.body)
    }

    @Throws(DownloadFailedException::class, InvalidAccessTokenException::class)
    private fun parseAccessTokenResponse(responseBody: String): TokenResponse {
        if (responseBody.isBlank()) {
            throw DownloadFailedException("Token response body is empty")
        }

        val tokenResponse = JsonUtils.deserialize(responseBody, TokenResponse::class.java)
            ?: throw InvalidAccessTokenException("Failed to parse token response")

        if (tokenResponse.accessToken.isNullOrBlank()) {
            throw InvalidAccessTokenException("Access token missing in response")
        }

        return tokenResponse
    }
}
