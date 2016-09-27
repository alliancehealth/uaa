package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UaaSamlIDPDocs extends InjectedMockContextTest {

  private String adminToken;

  private RandomValueStringGenerator generator = new RandomValueStringGenerator(10);

  private String requestBody;
  private Snippet requestFields = requestFields(
    fieldWithPath("name").type(STRING).attributes(key("constraints").value("Required")).description("Human readable name for the SAML SP."),
    fieldWithPath("entityId").type(STRING).attributes(key("constraints").value("Optional")).description("If provided, it should match the entityId in the SP metadata."),
    fieldWithPath("active").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("Defaults to true"),
    fieldWithPath("config").type(STRING).attributes(key("constraints").value("Required")).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
    fieldWithPath("config.metaDataLocation").type(STRING).attributes(key("constraints").value("Required")).description("The SAML SP Metadata - either an XML string or a URL that").optional(),
    fieldWithPath("config.metadataTrustCheck").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("Determines whether UAA should validate the SAML SP metadata.").optional()
  );
  private Snippet responseFields = responseFields(
    fieldWithPath("id").type(STRING).description("Unique identifier for this provider - GUID generated by the UAA."),
    fieldWithPath("name").type(STRING).description("Human readable name for the SAML SP."),
    fieldWithPath("entityId").type(STRING).description("The entity id of the SAML SP."),
    fieldWithPath("active").type(BOOLEAN).description("Defaults to true."),
    fieldWithPath("created").type(NUMBER).description("UAA sets this to the UTC creation date."),
    fieldWithPath("identityZoneId").type(STRING).description("Set to the zone that this provider will be active in. Determined by either."),
    fieldWithPath("lastModified").type(NUMBER).description("UAA sets this to the UTC last date of modification."),
    fieldWithPath("version").type(NUMBER).description("Version of the identity provider data. Clients can use this."),
    fieldWithPath("config").type(STRING).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
    fieldWithPath("config.metaDataLocation").type(STRING).description("The SAML SP Metadata - either an XML string or a URL that.").optional(),
    fieldWithPath("config.metadataTrustCheck").type(BOOLEAN).description("Determines whether UAA should validate the SAML SP metadata.").optional()

  );

  private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id.");
  private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.");

  @Before
  public void setup() throws Exception {
    adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "uaa.admin", null);
    String name = generator.generate();
    requestBody = "{\n" +
      "  \"name\" : \"" + name + "\",\n" +
      "  \"entityId\" : \""+ name +".cloudfoundry-saml-login\",\n" +
      "  \"active\" : true,\n" +
      "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"1\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true }\"" +
      "}";
  }

  @Test
  public void createServiceProvider() throws Exception {
    getMockMvc().perform(post("/saml/service-providers")
      .header("Authorization","Bearer " + adminToken)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    ).andExpect(status().isCreated())
      .andDo(document("{ClassName}/{methodName}",
        preprocessRequest(prettyPrint()),
        preprocessResponse(prettyPrint()),
        requestHeaders(
          headerWithName("Authorization").description("Bearer token containing `sps.write`"),
            IDENTITY_ZONE_ID_HEADER,
            IDENTITY_ZONE_SUBDOMAIN_HEADER
        ),
        requestFields,
        responseFields));
  }

  @Test
  public void updateServiceProvider() throws Exception {
    MockHttpServletResponse response = getMockMvc().perform(post("/saml/service-providers")
      .header("Authorization", "Bearer " + adminToken)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    ).andReturn().getResponse();
    SamlServiceProvider samlServiceProvider = JsonUtils.readValue(response.getContentAsString(), SamlServiceProvider.class);

    getMockMvc().perform(put("/saml/service-providers/"+samlServiceProvider.getId())
      .header("Authorization","Bearer " + adminToken)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    ).andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessRequest(prettyPrint()),
        preprocessResponse(prettyPrint()),
        requestHeaders(
          headerWithName("Authorization").description("Bearer token containing `sps.write`"),
            IDENTITY_ZONE_ID_HEADER,
            IDENTITY_ZONE_SUBDOMAIN_HEADER
        ),
        requestFields,
        responseFields));
  }

  @Test
  public void getServiceProvider() throws Exception {
    MockHttpServletResponse response = getMockMvc().perform(post("/saml/service-providers")
      .header("Authorization", "Bearer " + adminToken)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    ).andReturn().getResponse();
    SamlServiceProvider samlServiceProvider = JsonUtils.readValue(response.getContentAsString(), SamlServiceProvider.class);

    getMockMvc().perform(get("/saml/service-providers/"+samlServiceProvider.getId())
      .header("Authorization","Bearer " + adminToken)
    ).andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessRequest(prettyPrint()),
        preprocessResponse(prettyPrint()),
        requestHeaders(
          headerWithName("Authorization").description("Bearer token containing `sps.read`"),
            IDENTITY_ZONE_ID_HEADER,
            IDENTITY_ZONE_SUBDOMAIN_HEADER
        ),
        responseFields));
  }

  @Test
  public void getAllServiceProviders() throws Exception {
    Snippet responseFields = responseFields(
      fieldWithPath("[].id").type(STRING).description("Unique identifier for this provider - GUID generated by the UAA."),
      fieldWithPath("[].name").type(STRING).description("Human readable name for the SAML SP."),
      fieldWithPath("[].entityId").type(STRING).description("The entity id of the SAML SP."),
      fieldWithPath("[].active").type(BOOLEAN).description("Defaults to true."),
      fieldWithPath("[].created").type(NUMBER).description("UAA sets this to the UTC creation date."),
      fieldWithPath("[].identityZoneId").type(STRING).description("Set to the zone that this provider will be active in. Determined by either."),
      fieldWithPath("[].lastModified").type(NUMBER).description("UAA sets this to the UTC last date of modification."),
      fieldWithPath("[].version").type(NUMBER).description("Version of the identity provider data. Clients can use this."),
      fieldWithPath("[].config").type(STRING).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
      fieldWithPath("[].config.metaDataLocation").type(STRING).description("The SAML SP Metadata - either an XML string or a URL that.").optional(),
      fieldWithPath("[].config.metadataTrustCheck").type(BOOLEAN).description("Determines whether UAA should validate the SAML SP metadata.").optional()

    );

    getMockMvc().perform(post("/saml/service-providers")
      .header("Authorization", "Bearer " + adminToken)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    ).andReturn().getResponse();

    getMockMvc().perform(get("/saml/service-providers")
      .header("Authorization","Bearer " + adminToken)
    ).andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessRequest(prettyPrint()),
        preprocessResponse(prettyPrint()),
        requestHeaders(
          headerWithName("Authorization").description("Bearer token containing `sps.read`"),
            IDENTITY_ZONE_ID_HEADER,
            IDENTITY_ZONE_SUBDOMAIN_HEADER
        ),
        responseFields));
  }
}
