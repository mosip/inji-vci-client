package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.redirectToWeb

import io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization.ImplicitAuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.AuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.constants.OpenWebPageCallback
import io.mosip.vciclient.exception.InteractiveAuthorizationException

class RedirectToWebAuthorizationMethodService(
    val openWebPage: OpenWebPageCallback
) : AuthorizationMethodService {

    override fun type(): String {
        return InteractionType.RedirectToWeb.value
    }

    override suspend fun authorizeUser(requestData: AuthorizationRequestData): AuthorizationResponse {
        if (requestData !is ImplicitAuthorizationRequestData) {
            throw InteractiveAuthorizationException(
                "RedirectToWebAuthorizationHandler expects ImplicitAuthorizationRequestData " +
                        "but received ${requestData::class.simpleName}"
            )
        }

        val authUrl = AuthorizationUrlBuilder.build(
            baseUrl = requestData.authorizeUrl,
            clientId = requestData.clientMetadata.clientId,
            redirectUri = requestData.clientMetadata.redirectUri,
            scope = requestData.scope,
            state = requestData.pkceSession.state,
            codeChallenge = requestData.pkceSession.codeChallenge,
            nonce = requestData.pkceSession.nonce
        )
        val authorizationResponse = openWebPage(authUrl)

        if (authorizationResponse.containsKey("error")) {
            val error = authorizationResponse["error"] as? String
            val errorDescription = authorizationResponse["error_description"] as? String
            return AuthorizationResponse(
                authorizationCode = null,
                status = "error",
                error = error,
                errorDescription = errorDescription,
                authSession = null
            )
        }

        val code = authorizationResponse["code"] as? String
            ?: throw InteractiveAuthorizationException("Missing authorization_code in successful redirect response")

        return AuthorizationResponse(
            authorizationCode = code,
            status = "success",
            error = null,
            errorDescription = null,
            authSession = authorizationResponse["auth_session"] as? String
        )
    }

}

