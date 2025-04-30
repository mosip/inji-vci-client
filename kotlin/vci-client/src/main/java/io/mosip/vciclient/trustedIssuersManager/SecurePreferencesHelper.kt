package io.mosip.vciclient.trustedIssuersManager


import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecurePreferencesHelper {

    private const val PREF_FILE_NAME = "vci_trusted_issuers_secure_prefs"

    private fun getPrefs(context: Context) =
        EncryptedSharedPreferences.create(
            context,
            PREF_FILE_NAME,
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

    fun save(context: Context, key: String, value: String) {
        getPrefs(context).edit().putString(key, value).apply()
    }

    fun load(context: Context, key: String): String? {
        return getPrefs(context).getString(key, null)
    }

    fun remove(context: Context, key: String) {
        getPrefs(context).edit().remove(key).apply()
    }

    fun clearAll(context: Context) {
        getPrefs(context).edit().clear().apply()
    }
}
