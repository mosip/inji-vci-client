package io.mosip.vciclient.exception

class DPoPException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-013",
        message = message ?: ""
    )

    constructor(
        message: String?,
        issuerErrorCode: String? = null,
        issuerErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-013",
        message = message ?: "",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    )
}
