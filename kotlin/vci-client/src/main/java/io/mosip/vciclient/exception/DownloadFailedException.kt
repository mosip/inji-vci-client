package io.mosip.vciclient.exception

class DownloadFailedException(
    message: String?,
) : VCIClientException("VCI-002", "Failed to download Credential: $message")