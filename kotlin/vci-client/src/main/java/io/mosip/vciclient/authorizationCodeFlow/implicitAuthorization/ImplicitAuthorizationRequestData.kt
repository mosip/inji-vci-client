package io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization

import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.pkce.PKCESessionManager

data class ImplicitAuthorizationRequestData(
    val authorizeUrl: String,
    val clientMetadata: ClientMetadata,
    val pkceSession: PKCESessionManager.PKCESession,
    val scope: String,
    val dpopJkt: String,
    val pushedAuthorizationRequestEndpoint: String? = null,
    val tokenEndpointAuthMethodsSupported: List<String>? = null,
    val requirePushedAuthorizationRequests: Boolean? = null,
) : AuthorizationRequestData()