package io.mosip.vciclient.testData

internal val wellKnownResponseMap = mapOf(
    "credential_issuer" to "https://mock.issuer",
    "credential_endpoint" to "https://mock.issuer/endpoint",
    "authorization_servers" to listOf("https://auth"),
    "credential_configurations_supported" to mapOf(
        "UniversityDegreeCredential" to mapOf(
            "format" to "ldp_vc",
            "scope" to "degree",
            "credential_definition" to mapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "type" to listOf("VerifiableCredential")
            )
        )
    )
)

internal val wellKnownResponse = """
        {
          "credential_issuer": "https://mock.issuer",
          "credential_endpoint": "https://mock.issuer/endpoint",
          "authorization_servers": ["https://auth"],
          "credential_configurations_supported": {
            "UniversityDegreeCredential": {
              "format": "ldp_vc",
              "scope": "degree",
              "credential_definition": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"]
              }
            }
          }
        }
    """.trimIndent()