package com.example.vciclient

import android.content.Intent
import android.os.Bundle
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.vciclient.ui.theme.VCIClientTheme
import com.example.vciclient.util.Constants
import com.example.vciclient.util.PemConverter
import io.mosip.vciclient.VCIClient
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.proof.jwt.JWTProof
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.TokenResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature


lateinit var keyPair: KeyPair
lateinit var authorizationService: AuthorizationService
lateinit var authState: AuthState

class MainActivity : ComponentActivity() {
    private val activityResultLauncher: ActivityResultLauncher<Intent> =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                val data: Intent? = result.data
                println("data ${data.toString()}")
                handleAuthorizationResponse(data!!)
            } else {
                println("result -> $result")
            }
        }

    private fun handleAuthorizationResponse(intent: Intent) {
        val authorizationResponse: AuthorizationResponse? = AuthorizationResponse.fromIntent(intent)
        val error = AuthorizationException.fromIntent(intent)

        authState = AuthState(authorizationResponse, error)
        val tokenExchangeRequest = authorizationResponse?.createTokenExchangeRequest()!!
        authorizationService.performTokenRequest(tokenExchangeRequest) { response, exception ->
            if (exception != null) {
                authState = AuthState()
            } else {
                if (response != null) {
                    authState.update(response, exception)
                    downloadCredential(response)
                }
            }
        }
    }

    private fun downloadCredential(tokenResponse: TokenResponse) {
        generateKeyPair()
        val accessToken = tokenResponse.accessToken!!
        val publicKeyInPem = PemConverter(keyPair.public).toPem()
        Log.d(javaClass.simpleName, "About to call credential api")
        val thread = Thread {
            try {
                //TODO: Create JWT
                val jwtValue = ""
                val credentialResponse: CredentialResponse? = VCIClient("example-vci-client").requestCredential(
                    issuerMetaData = IssuerMetaData(
                        Constants.CREDENTIAL_AUDIENCE,
                        Constants.CREDENTIAL_ENDPOINT,
                        Constants.DOWNLOAD_TIMEOUT,
                        Constants.CREDENTIAL_TYPE,
                        null,
                        Constants.CREDENTIAL_FORMAT
                    ),
                    proof = JWTProof(jwtValue),
                    accessToken = accessToken
                )
                if (credentialResponse != null) {
                    val text = "Download success"
                    println(credentialResponse.toString())
                    val duration = Toast.LENGTH_LONG
                    Looper.prepare()
                    val toast = Toast.makeText(this, text, duration) // in Activity
                    toast.show()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        thread.start()
    }

    @Composable
    private fun handleVCAuthAndDownload() = {
        ->
        Log.d(javaClass.simpleName, "ABout to start authorization")

        val config =
            AuthorizationServiceConfiguration(
                Constants.URL_AUTHORIZATION,
                Constants.URL_TOKEN_EXCHANGE
            )
        val request: AuthorizationRequest = AuthorizationRequest.Builder(
            config,
            Constants.CLIENT_ID,
            ResponseTypeValues.CODE,
            Constants.URL_AUTH_REDIRECT
        )
            .setScopes(Constants.SCOPE)
            .build()

        val authorizationRequestIntent = authorizationService.getAuthorizationRequestIntent(request)
        activityResultLauncher.launch(authorizationRequestIntent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        authorizationService = AuthorizationService(this)
        setContent {
            Button(onClick = handleVCAuthAndDownload()) {
                Text(text = "Get VC")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        authorizationService.dispose()
    }
}


private fun signer(inputByteArray: ByteArray): ByteArray {
    val signature: Signature = Signature.getInstance("SHA256withRSA")
    signature.initSign(keyPair.private)
    val sign = signature.run {
        update(inputByteArray)
        sign()
    }
    return sign
}

private fun generateKeyPair() {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val keySpecBuilder = getKeyPairGenSpecBuilder("CredentialRequest_KeyPair")
    keyPairGenerator.initialize(keySpecBuilder.build())
    keyPair = keyPairGenerator.generateKeyPair()
}

private fun getKeyPairGenSpecBuilder(alias: String): KeyGenParameterSpec.Builder {
    val purposes =
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY

    return KeyGenParameterSpec.Builder(alias, purposes)
        .setKeySize(4096)
        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello000o $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    VCIClientTheme {
        Greeting("Android")
    }
}