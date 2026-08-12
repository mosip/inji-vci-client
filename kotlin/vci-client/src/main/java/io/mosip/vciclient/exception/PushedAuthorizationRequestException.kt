package io.mosip.vciclient.exception

class PushedAuthorizationRequestException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-014",
        message = "Failed to push authorization request: $message"
    )

    constructor(
        message: String?,
        issuerErrorCode: String? = null,
        issuerErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-014",
        message = "Failed to push authorization request: $message",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    )
}
