package goSamlProtocol20

import (
	"encoding/xml"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	//xsdt "github.com/tecnickcom/go-xsd-pkg/xsdt"
)

// --- Request

func TestUnmarshalAuthNRequest(t *testing.T) {

	type AuthnRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		TAuthnRequestType
	}

	xmlstr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="theID" Version="theVersion" ProviderName="theProviderName" IssueInstant="2014-07-16T23:52:45Z" Destination="theDestination" ProtocolBinding="theProtocolBinding" AssertionConsumerServiceURL="theAssertionConsumerServiceURL" AssertionConsumerServiceIndex="123">
  <saml:Issuer>theIssuer</saml:Issuer>
  <samlp:NameIDPolicy Format="theFormat" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>theAuthnContextClassRef</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`

	data := new(AuthnRequest)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}
	assert.Equal(t, data.ID.String(), "theID")
	assert.Equal(t, data.ProviderName.String(), "theProviderName")
	assert.Equal(t, data.Destination.String(), "theDestination")
	assert.Equal(t, data.ProtocolBinding.String(), "theProtocolBinding")
	assert.Equal(t, data.AssertionConsumerServiceURL.String(), "theAssertionConsumerServiceURL")
	assert.Equal(t, data.AssertionConsumerServiceIndex.N(), uint16(123))
	assert.Equal(t, data.Issuer.XCDATA, "theIssuer")
	assert.Equal(t, data.NameIDPolicy.Format.String(), "theFormat")
	assert.Equal(t, data.RequestedAuthnContext.AuthnContextClassRefs[0].String(), "theAuthnContextClassRef")

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<AuthnContextClassRef xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">theAuthnContextClassRef</AuthnContextClassRef>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestUnmarshalAuthNRequest_Defaults(t *testing.T) {

	type AuthnRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		TAuthnRequestType
	}

	xmlstr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>`

	data := new(AuthnRequest)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}
	assert.Equal(t, data.ID.String(), "")
	assert.Equal(t, data.ProviderName.String(), "")
	assert.Equal(t, data.Destination.String(), "")
	assert.Equal(t, data.ProtocolBinding.String(), "")
	assert.Equal(t, data.AssertionConsumerServiceURL.String(), "")
	assert.Nil(t, data.AssertionConsumerServiceIndex)
	assert.Nil(t, data.Issuer)
	assert.Nil(t, data.NameIDPolicy)
	assert.Empty(t, data.RequestedAuthnContext)

}

func TestUnmarshalAuthNRequestSig(t *testing.T) {

	type AuthnRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		TAuthnRequestType
	}

	xmlstr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx41d8ef22-e612-8c50-9960-1b16f15741b3" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#pfx41d8ef22-e612-8c50-9960-1b16f15741b3">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>yJN6cXUwQxTmMEsPesBP2NkqYFI=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`

	data := new(AuthnRequest)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</X509Certificate>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

// --- Response

func TestXMLUnmarshalResponse(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<Conditions xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx0922d66a-164a-8a75-8ae5-6d6a674271e1" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx0922d66a-164a-8a75-8ae5-6d6a674271e1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>UI1y07kpKQB8glgIvs29ZrV3PvA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>iochcQXiG1ztWtpcDLxcEFhNh+o/QDqWcdYk/WkR45B++ZNBS74EmVKtjRaVot/W3MqBfwwZ8Q+fQ+fkOA6yDCky/VZ77SHJnQxNbI+HfWdLIWyEsvN3+h0Zj3X6gpP1kpL2zIfqY59T57VkP9F12uuSQX7RlAQbAghQZMGSayE=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</X509Certificate>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedMessage(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx8d3a32ee-eb6b-43b3-ef06-181daa9d634b" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx8d3a32ee-eb6b-43b3-ef06-181daa9d634b"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>nvBfiZSvUinBsX8tM1VMX6GKYgE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>1b/idZv5yxwzOvJx5mOJoYDdJHubKMKWSvYRAhhMwGOy3MfI7py/yL2B1t9Fuvj0KhE4xXmSigSGus0/ErkiEniEAdNHEkCtzQWATE2IIw/atOlvGhoRLtIBAFG+dYvL0tzo3O/IWSWE1UGjpNVkHz44fjxG8MJYKrvt1RnhXpE=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<AuthnContextClassRef xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedMessageAndAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx26a5c43b-3d19-125f-d950-3d8b32a2a7f4" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx26a5c43b-3d19-125f-d950-3d8b32a2a7f4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Div0ig5R+XuLIffFMw2ZxSDE6Ws=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>szx5jF+4nBNV8++JE7c80Q3tWxtaIKDK2gw10rPFNjZCVdCn+5COfYXNAncFiCzQmcRHTbby4zrYyi56QCvniZCQvNf90BapiCYcDkxgg9oaDIIHmNbLIDyBma175bcxwkC2YApiPo8N8/H0YThZBy64rBCMS8vFvVxvUVsP2Ww=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx6b7b81db-74d8-bebc-3010-f58a0c204fff" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx6b7b81db-74d8-bebc-3010-f58a0c204fff"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>wYMNGx5wxZpI9WBSBG5Id79BOOw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gHZNW55aHs4YjJX53MX0q8taDnv0Di7Jq2sILKs9danQWrjtyLPNHTvuAs1nP1Tl5bI3+jUlw4Ck6KQp2XcAYdJmvJwPZ3jGzC11jVqqL7TlHX/si7urOQudP37pWHdJNjmqTh4l1OkUWNypaI4SeZuBkVeNX+ttQdAI4FDmLsI=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), `<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion" SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</NameID>`) {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseEncryptedAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>CjM9FrusQA3HJF9xwnYOoiyhE4D1ie6b+DkuWRaT50Cv1XdiiRIRev7Cx0ZjAqZr9MX3ayYc4GZ5sRLioPIgTkB4XXZk0+R4bfiLKI6g4RdvexVVEHKJSiwMHeFbGZxEaAlCT0hBrAo/aJAg7IG2821PCYvQ0C50JJIfBuVnVgY=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<CipherValue xmlns=\"http://www.w3.org/2001/04/xmlenc#\">WGj9w6BBPNGdkLRr9Oi5d") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedAndEncryptedAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>XUZAdNi/1jOAS0LRS1Fx51GBWtvSJJypvgyR13bN9HQPgYeAeeUAXcYFsUvKHGzEZLJ+fkUz3AozS/fARz4mKBjT4Z5HVy3f2MxT86z/mAnnGw4/vOPWOdLw/6UcMxvT2n/MQZ6Fw44UWC1j4kM5UiYDGG8nEEYzSLhdvNKMnKg=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<CipherValue xmlns=\"http://www.w3.org/2001/04/xmlenc#\">abMeXys3/QSrisZE+TCZu4Tcb") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedMessageAndEncryptedAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx6eabde59-bf44-6188-a67a-7cf46e1bffb0" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx6eabde59-bf44-6188-a67a-7cf46e1bffb0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>SNG7O7/CWZ9UgtTb/OiUJLRMnf8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>TEd+a3Mn85ysgJwRHFF3zoqlJ1C1piR/9csg7LyhJP7iDfkQPNMg+hcSJEY7+6grOpg6O6kimhkA0a7a7OPHDjlhHLD/2KUYYjILUkVrNI4t4CXZublO65X/xRHVcWbFQTaZf4fvY6AG7wdXj88y434mQ0uSxsKWZMh4sHKm09M=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>CjM9FrusQA3HJF9xwnYOoiyhE4D1ie6b+DkuWRaT50Cv1XdiiRIRev7Cx0ZjAqZr9MX3ayYc4GZ5sRLioPIgTkB4XXZk0+R4bfiLKI6g4RdvexVVEHKJSiwMHeFbGZxEaAlCT0hBrAo/aJAg7IG2821PCYvQ0C50JJIfBuVnVgY=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalResponseSignedMessageAndSignedAndEncryptedAssertion(t *testing.T) {

	type Response struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		TResponseType
	}

	xmlstr := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxfbd8bb53-3c75-f8c9-3b2e-1ea2dd644d1a" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxfbd8bb53-3c75-f8c9-3b2e-1ea2dd644d1a"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>X17fwqmYLSrXs7e8Cpf8KciKzos=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>1UNPae+nmpysFyMc1rQTbRdhnbjqWUbLMe5UJupiZJ2XKAdj5WqJP8U6WtMGg9nG8xhqtiI6TlkEhHMRR6TsVEjFm1cH4Y2EZVjT36xks5hjjfZTehby1VZkcnHQuIp/Z0aA80dl2T9jyfRAeMNzU5oFTkMhULdAJLQIJFQcH3c=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>XUZAdNi/1jOAS0LRS1Fx51GBWtvSJJypvgyR13bN9HQPgYeAeeUAXcYFsUvKHGzEZLJ+fkUz3AozS/fARz4mKBjT4Z5HVy3f2MxT86z/mAnnGw4/vOPWOdLw/6UcMxvT2n/MQZ6Fw44UWC1j4kM5UiYDGG8nEEYzSLhdvNKMnKg=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

	data := new(Response)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<CipherValue xmlns=\"http://www.w3.org/2001/04/xmlenc#\">abMeXys3/QSrisZE+TCZu4T") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

// --- Logout Request

func TestXMLUnmarshalLogoutRequest(t *testing.T) {

	type LogoutRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
		TLogoutRequestType
	}

	xmlstr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://idp.example.com/SingleLogoutService.php">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
</samlp:LogoutRequest>`

	data := new(LogoutRequest)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), `<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion" SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</NameID>`) {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalLogoutRequestSignature(t *testing.T) {

	type LogoutRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
		TLogoutRequestType
	}

	xmlstr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://idp.example.com/SingleLogoutService.php">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>Q9PRlugQZKSBt+Ed9i6bKUGWND0=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>e861LsuFQi4dmtZanZlFjCtHym5SLhjwRZMxW2DSMhPwWxg7tD2vOH7mgqqFd3Syt9Q6VYSiWyIdYkpf4jsVTGZDXKk2zQbUFG/avRC9EsgMIw7UfeMwFw0D/XGDqihV9YoQEc85wGdbafQOGhMXBxkt+1Ba37ok8mCZAEFlZpw=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
</samlp:LogoutRequest>`

	data := new(LogoutRequest)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<DigestValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\">Q9PRlugQZKSBt+Ed9i6bKUGWND0=</DigestValue>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

// --- Logout Response

func TestXMLUnmarshalLogoutResponse(t *testing.T) {

	type LogoutResponse struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
		TStatusResponseType
	}

	xmlstr := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_6c3737282f007720e736f0f4028feed8cb9b40291c" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>`

	data := new(LogoutResponse)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<StatusCode xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"></StatusCode>") {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}

func TestXMLUnmarshalLogoutResponseSignature(t *testing.T) {

	type LogoutResponse struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
		TStatusResponseType
	}

	xmlstr := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxe335499f-e73b-80bd-60c4-1628984aed4f" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#pfxe335499f-e73b-80bd-60c4-1628984aed4f">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>PusFPAn+RUZV+fBvwPffNMOENwE=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>UEsyvBbilIQFCYk5i63NKwohkV/RGhVlT+Ajx1XBarFyB8rPCYe6NWnoqbzimKiBZaL2eSINyBLzyFdHqbI+K7qP9rmHJmIC8g5M84GJrpHoaIYJkmLjSMf4APTAiKeuW8dVvcnrrzHb8fFV/2Ob6nWG2+K3ixvH1MWh5R0bGbE=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>`

	data := new(LogoutResponse)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), `<SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">UEsyvBbilIQFCYk5i63NKwohkV/RGhVlT+Ajx1XBarFyB8rPCYe6NWnoqbzimKiBZaL2eSINyBLzyFdHqbI+K7qP9rmHJmIC8g5M84GJrpHoaIYJkmLjSMf4APTAiKeuW8dVvcnrrzHb8fFV/2Ob6nWG2+K3ixvH1MWh5R0bGbE=</SignatureValue>`) {
		t.Error(fmt.Errorf("The resulting XML is not correct: %s", string(xmldata)))
	}
}
