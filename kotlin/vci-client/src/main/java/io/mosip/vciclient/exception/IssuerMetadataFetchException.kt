package io.mosip.vciclient.exception

class IssuerMetadataFetchException(message: String?) : VCIClientException("VCI-009","Failed to fetch issuerMetadata - $message")
