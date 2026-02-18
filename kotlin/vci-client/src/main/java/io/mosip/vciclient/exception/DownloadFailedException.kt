package io.mosip.vciclient.exception

class DownloadFailedException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-002",
        message = "Failed to download Credential: $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-002",
        message = "Failed to download Credential: $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
