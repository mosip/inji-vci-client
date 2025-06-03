package io.mosip.vciclient.trustedIssuersManager

import android.content.Context
import io.mosip.vciclient.common.JsonUtils

class TrustedIssuerRegistry(private val context: Context) {

    private val key = "trusted_issuers_vci"

    fun isTrusted(issuer: String): Boolean {
        return loadTrustedIssuers().contains(issuer)
    }

    fun markTrusted(issuer: String) {
        val issuers = loadTrustedIssuers().toMutableSet()
        issuers.add(issuer)
        saveTrustedIssuers(issuers)
    }

    private fun loadTrustedIssuers(): Set<String> {
        return try {
            val issuerJson: String? = SecurePreferencesHelper.load(context, key)
            if (!issuerJson.isNullOrEmpty()) {
                JsonUtils.deserialize(issuerJson, Array<String>::class.java)?.toSet() ?: emptySet()
            } else {
                emptySet()
            }
        } catch (e: Exception) {
            emptySet()
        }
    }

    private fun saveTrustedIssuers(issuers: Set<String>) {
        val json = JsonUtils.serialize(issuers.toList())
        SecurePreferencesHelper.save(context, key, json)
    }
}
