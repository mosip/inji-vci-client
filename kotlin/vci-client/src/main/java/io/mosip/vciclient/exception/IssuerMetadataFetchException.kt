package io.mosip.vciclient.exception

class IssuerMetadataFetchException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-009",
        message = "Failed to fetch issuerMetadata - $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-009",
        message = "Failed to fetch issuerMetadata: $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
