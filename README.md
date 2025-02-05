# INJI VCI Client


INJI VCI client library is designed specifically for interacting with the Credential Endpoint of the OpenID4VCI specification.

- Primary focus: Handling the credential request and response flow. 

As per OpenID4VCI spec, once a client has obtained an access token via an authorization flow, it can request a Verifiable Credential (VC) from the Credential Endpoint.
This library focuses on that HTTP interaction with the credential issuer.

## Features

- Implements credential request (POST /credential) according to OpenID4VCI
- Handles credential response parsing (ldp_vc, mso_mdoc)
- Provides error handling for failure cases (e.g., Download request timeout, Download failure)


## Supported Credential formats
1. `ldp_Vc`
2. `mso_mdoc`

## Specification followed
Follows the draft 13 OpenID4VCI specification

## Supported Environments

This library is designed to be used across below-mentioned environment(s):
- Android : This library provides full support for Android environments. For more information on using this library in Android, refer to this [guide](./kotlin/README.md).
- iOS: This library is also available as a  Swift package. For more information, refer [here](https://github.com/mosip/inji-vci-client-ios-swift).




