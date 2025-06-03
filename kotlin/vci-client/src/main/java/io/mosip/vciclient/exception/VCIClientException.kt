package io.mosip.vciclient.exception

open class VCIClientException(
    val code: String,
    override val message: String,
) : Exception(message)
