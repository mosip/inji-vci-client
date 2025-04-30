package com.example.vciclient.util

import android.net.Uri
import io.mosip.vciclient.constants.CredentialFormat

class Constants {
    companion object {
        const val DOWNLOAD_TIMEOUT: Int = 30000
        const val CREDENTIAL_ENDPOINT: String = "<credential-endpoint>"

        const val CLIENT_ID = "<client-id>"
        val URL_AUTHORIZATION: Uri = Uri.parse("<authorization-endpoint>")
        val URL_AUTH_REDIRECT: Uri = Uri.parse("<redirect-uri>")
        val URL_TOKEN_EXCHANGE: Uri =
            Uri.parse("<token-endpoint>")
        const val SCOPE = "<scope>"
        const val CREDENTIAL_AUDIENCE = "<credential-audience>"
        val CREDENTIAL_TYPE = listOf("<credential-type1>", "<credential-type1>")
        val CREDENTIAL_FORMAT = CredentialFormat.LDP_VC
    }
}
