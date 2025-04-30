package io.mosip.vciclient.authorizationServer

import android.util.Log
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.exception.AuthServerDiscoveryException
import io.mosip.vciclient.grant.GrantType
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

class AuthServerResolver {
    suspend fun resolveForPreAuth(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
    ): AuthServerMetadata {
        val offerGrantAuthServer = credentialOffer.grants?.preAuthorizedGrant?.authorizationServer
        return resolveAuthServer(
            offerGrantAuthServer,
            issuerMetadata,
            expectedGrantType = GrantType.PRE_AUTHORIZED.value,
            credentialIssuer = issuerMetadata.credentialAudience
        )
    }

    suspend fun resolveForAuthCode(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
    ): AuthServerMetadata {
        val offerGrantAuthServer =
            credentialOffer.grants?.authorizationCodeGrant?.authorizationServer
        return resolveAuthServer(
            offerGrantAuthServer,
            issuerMetadata,
            expectedGrantType = GrantType.AUTHORIZATION_CODE.value,
            credentialIssuer = issuerMetadata.credentialAudience
        )
    }

    suspend fun resolveForAuthCode(issuerMetadata: IssuerMetadata): AuthServerMetadata {
        return resolveAuthServer(
            null,
            issuerMetadata,
            GrantType.AUTHORIZATION_CODE.value,
            issuerMetadata.credentialAudience
        )
    }

    private suspend fun resolveAuthServer(
        offerGrantAuthServer: String?,
        issuerMetadata: IssuerMetadata,
        expectedGrantType: String,
        credentialIssuer: String,
    ): AuthServerMetadata {
        val authServers = issuerMetadata.authorizationServers
        return when {
            authServers?.size == 1 -> {
                discoverAndValidate(authServers.first(), expectedGrantType)
            }

            !offerGrantAuthServer.isNullOrBlank() -> {
                discoverAndValidate(offerGrantAuthServer, expectedGrantType)
            }

            !authServers.isNullOrEmpty() -> {
                resolveFirstValid(authServers, expectedGrantType)
            }

            else -> {
                discoverAndValidate(credentialIssuer, expectedGrantType)
            }
        }
    }

    private suspend fun discoverAndValidate(
        authServerUrl: String,
        expectedGrantType: String,
    ): AuthServerMetadata {
        val authServerMetadata = AuthServerDiscoveryService().discover(authServerUrl)

        if (authServerUrl.isNotBlank() && authServerMetadata.issuer != authServerUrl) {
            throw AuthServerDiscoveryException("Issuer mismatch: Expected '$authServerUrl', got '${authServerMetadata.issuer}'")
        }

        if ((expectedGrantType !in ((authServerMetadata.grantTypesSupported) ?: listOf(
                GrantType.AUTHORIZATION_CODE.value, GrantType.IMPLICIT.value
            )) && expectedGrantType != GrantType.PRE_AUTHORIZED.value)
        ) {
            throw AuthServerDiscoveryException("Grant type '$expectedGrantType' not supported by auth server.")
        }

        if (expectedGrantType == GrantType.AUTHORIZATION_CODE.value && authServerMetadata.authorizationEndpoint.isNullOrBlank()) {
            throw AuthServerDiscoveryException("Missing authorization_endpoint for authorization_code flow.")
        }

        return authServerMetadata
    }

    private suspend fun resolveFirstValid(
        authServers: List<String>,
        expectedGrantType: String,
    ): AuthServerMetadata = coroutineScope {
        val deferreds = authServers.map { authServer ->
            async {
                runCatching {
                    discoverAndValidate(authServer, expectedGrantType)
                }.getOrNull()
            }
        }

        deferreds.firstNotNullOfOrNull { it.await() }
            ?: throw AuthServerDiscoveryException("None of the authorization servers responded with valid metadata.")
    }

}
