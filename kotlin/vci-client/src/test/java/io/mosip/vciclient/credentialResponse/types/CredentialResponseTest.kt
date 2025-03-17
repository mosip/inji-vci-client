package io.mosip.vciclient.credentialResponse.types

import com.google.gson.Gson
import io.mosip.vciclient.credentialResponse.CredentialResponse
import org.junit.Assert.assertEquals
import org.junit.Test

class CredentialResponseTest {

    @Test
    fun `should return json string for ldpVc credential response`() {
        val responseBody =
            "{\"credential\":{\"id\":\"https://domain.net/credentials/12345-87435\",\"type\":[\"VerifiableCredential\"],\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofValue\":\"23sx\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"issuer\":\"https://domain.net/.well-known/issuer.json\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuanceDate\":\"2024-04-14T16:04:35.304Z\",\"expirationDate\":\"2024-07-28T11:41:43.216Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"}}}"
        val vcredentialResponse: CredentialResponse =
            Gson().fromJson(responseBody, CredentialResponse::class.java)

        assertEquals(
            responseBody,
            vcredentialResponse.toJsonString()
        )
    }

    @Test
    fun `should return json string for mdoc credential response`() {
        val responseBody =
            "{\"credential\":\"omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIYJZAdUwggHRMIIBdqADAgECAhRgb0VFosmsnekhZTiIOQGRdAgQ1jAKBggqhkjOPQQDAjBoMQswCQYDVQQGEwJJTjESMBAGA1UECAwJS2FybmF0YWthMQwwCgYDVQQHDANCTFIxDjAMBgNVBAoMBU1PU0lQMQ4wDAYDVQQLDAVNT1NJUDEXMBUGA1UEAwwOTW9jayBWQyBJc3N1ZXIwHhcNMjQwODIxMDgyMjUxWhcNMjUwODIxMDgyMjUxWjBoMQswCQYDVQQGEwJJTjESMBAGA1UECAwJS2FybmF0YWthMQwwCgYDVQQHDANCTFIxDjAMBgNVBAoMBU1PU0lQMQ4wDAYDVQQLDAVNT1NJUDEXMBUGA1UEAwwOTW9jayBWQyBJc3N1ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQmOaMJLUXdkU8sCCwvsvUfJSjssUgh9BiBKyT2qQLPXonS1WoUJK2qTu_PpdKpTEdGZqTp_HT86j_daCCPW8dIMAoGCCqGSM49BAMCA0kAMEYCIQDjgXGKG8BBB0vXy4NQPZDBA5fRcc95hXDSB1KlyJvu9gIhAOmxov_gfS_xD6ahp0-SZ8Jjdip48sVlKgpoQ-kQjYxZWQHUMIIB0DCCAXagAwIBAgIUYjk5coftHffgRQYrnIoBkXQK5_IwCgYIKoZIzj0EAwIwaDELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTEMMAoGA1UEBwwDQkxSMQ4wDAYDVQQKDAVNT1NJUDEOMAwGA1UECwwFTU9TSVAxFzAVBgNVBAMMDk1vY2sgVkMgSXNzdWVyMB4XDTI0MDgyMTA4MjU1N1oXDTI1MDgyMTA4MjU1N1owaDELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTEMMAoGA1UEBwwDQkxSMQ4wDAYDVQQKDAVNT1NJUDEOMAwGA1UECwwFTU9TSVAxFzAVBgNVBAMMDk1vY2sgVkMgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEChbpNVdfBlr-m793aA--A1WQhs5NeH_LY_1pJT9_Dc6exesc5OOruUI7FHvo_PjwyB5JWREvHEjk0ZGZhDq2DTAKBggqhkjOPQQDAgNIADBFAiEAmpdmRP-RQqGyumczWWkQS3y9UbqEf3WhEDHtvO0oPP4CIH38cVKrAwRv3Uu3jPFqrwDJY_8ET2EbpOQdIbBfE3zNWQJKpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBlcW9yZy5pc28uMTgwMTMuNS4xbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlgg1JEBfSLNO2vedAfnkk0NJhonng8QP6vTpe6EKI7eL3wGWCDCVnYFuty1v8jUx-QGiSdwu_1Vzasjk_DxMHP9WhV7ywNYII4dSMm0ZELjw8ml5gvQvve-MOrrmIJqaiK3UAKy49vhAVggeAmWHVTwVV8eBhYPDwonNWNbvC2yIggDot5S2zbk8nkEWCAs0XRbAxKYXBGvAJ51357woRDIZH6DNsAdgjPQFbLLSABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIMQT0ukLNay9co4MBSy9Z8AN91znyG8FtjQd_8atnpBlIlggfR2TQmaT4xfz01HCVOc7C9Hrnt-qUazM2pUt4NLA8wBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMDktMDNUMDY6MTI6MjdaaXZhbGlkRnJvbcB0MjAyNC0wOS0wM1QwNjoxMjoyN1pqdmFsaWRVbnRpbMB2MTAwMDAwLTAxLTAxVDAwOjAwOjAwWlhAVv2oPaEo5TxPVSbyI_vUL1A81O4NneVuYIxb2RtiLySIkB0feiWaWIWtKMU1amHotHoEhBCZ-VaPYLMw3fsOL2puYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYjYGFifpGhkaWdlc3RJRAJmcmFuZG9tUG2FLLW-amGqmgxhF71nQ-dxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyMy0wMS0wMSwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwNDMtMDEtMDF92BhYWqRoZGlnZXN0SUQGZnJhbmRvbVDcl4VzmY5oXohcs2H4bJdGcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVnMTIzNDU2N9gYWFikaGRpZ2VzdElEA2ZyYW5kb21QIL6_sBEAsnZUVxjDD0BsyHFlbGVtZW50SWRlbnRpZmllcmppc3N1ZV9kYXRlbGVsZW1lbnRWYWx1ZWoyMDI0LTAxLTEy2BhYWaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWxlbGVtZW50VmFsdWVmSXNsYW5k2BhYWaRoZGlnZXN0SUQEZnJhbmRvbVCDuJZw1tn5v1LYPe7cC_ZicWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZWoyMDI1LTAxLTEy2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE=\"}"

        val vcCredentialResponse: CredentialResponse =
            Gson().fromJson(responseBody, CredentialResponse::class.java)

        assertEquals(
            responseBody,
            vcCredentialResponse.toJsonString()
        )
    }
}
