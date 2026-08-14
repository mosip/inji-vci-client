package io.mosip.vciclient.exception

class IllegalArgumentException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-012",
        message = message ?: "An illegal argument was provided."
    )

    constructor(
        message: String?,
        issuerErrorCode: String? = null,
        issuerErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-012",
        message = message ?: "An illegal argument was provided.",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    )
}
