package io.mosip.vciclient.exception

class NetworkRequestFailedException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-006",
        message = "Network request failed, details - $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-006",
        message = "Network request failed, details - $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
