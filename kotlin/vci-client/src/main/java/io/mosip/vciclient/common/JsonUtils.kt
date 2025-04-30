package io.mosip.vciclient.common

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder

/**
 *  Created singleton instance of Gson and use it in the library to avoid expensive calls
 *  Link - https://groups.google.com/g/google-gson/c/rhIJ4wi5IRE
 */
class JsonUtils {
    companion object {
        private val gsonForSerialization: Gson = GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .disableHtmlEscaping()
            .create()

        private val gsonForDeserialization: Gson = GsonBuilder()
            .create()

        fun serialize(obj: Any): String {
            return gsonForSerialization.toJson(obj)
        }

        fun <T> deserialize(json: String, clazz: Class<T>): T? {
            return if (json.isNullOrEmpty()) {
                null
            } else {
                gsonForDeserialization.fromJson(json, clazz)
            }
        }

        fun toMap(body: String): Map<String, Any> {
            return if (body.isBlank()) emptyMap()
            else gsonForDeserialization.fromJson(
                body,
                object : com.google.gson.reflect.TypeToken<Map<String, Any>>() {}.type
            )
        }
    }
}