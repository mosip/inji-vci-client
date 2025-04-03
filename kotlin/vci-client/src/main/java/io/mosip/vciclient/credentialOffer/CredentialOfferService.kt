package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.URLDecoder

class CredentialOfferService {

    fun handleByValueOffer(encodedOffer: String): CredentialOffer {
        val decodedOffer = URLDecoder.decode(encodedOffer, "UTF-8")
        val credentialOffer = (JsonUtils.deserialize(decodedOffer, CredentialOffer::class.java)
            ?: throw OfferFetchFailedException("Invalid credential offer JSON"))
        CredentialOfferValidator.validate(credentialOffer)
        return credentialOffer
    }

    fun handleByReferenceOffer(url: String): CredentialOffer {
        val response = NetworkManager.sendRequest(
            url = url,
            method = HttpMethod.GET,
            headers = mapOf("Accept" to "application/json")
        )
        val body = response.body

        if ( body.isBlank()) {
            throw OfferFetchFailedException("Failed to fetch credential offer from $url")
        }

        val credentialOffer = (JsonUtils.deserialize(body, CredentialOffer::class.java)
            ?: throw OfferFetchFailedException("Invalid credential offer JSON"))
        CredentialOfferValidator.validate(credentialOffer)
        return credentialOffer
    }

}