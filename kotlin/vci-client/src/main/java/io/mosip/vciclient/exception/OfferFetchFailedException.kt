package io.mosip.vciclient.exception

class OfferFetchFailedException(message: String?) :
    VCIClientException("VCI-008", "Download failed due to fetching credentialOffer $message")