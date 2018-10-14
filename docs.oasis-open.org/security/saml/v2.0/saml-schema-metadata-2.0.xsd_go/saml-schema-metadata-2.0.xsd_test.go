package goSamlMetadata20

import (
	"encoding/xml"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	//"github.com/davecgh/go-spew/spew"
	xsdt "github.com/tecnickcom/go-xsd-pkg/xsdt"
)

func TestMarshalEntityDescriptor(t *testing.T) {

	// EntitiesDescriptor represents the SAML object of the same name.
	type EntityDescriptor struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		TEntityDescriptorType
	}

	data := new(EntityDescriptor)
	// fmt.Printf("\n\n%+v\n\n", data) // Print struct

	data.Organization = nil
	data.EntityID = "http://127.0.0.1:8000/metadata"
	data.AttributeAuthorityDescriptors = nil
	data.Extensions = nil
	data.AffiliationDescriptor = nil
	data.ValidUntil = "2017-01-04T10:39:21.942036958Z"
	data.CacheDuration = "PT48H"
	data.ID = "123"
	data.Signature = nil
	data.AuthnAuthorityDescriptors = nil
	data.PDPDescriptors = nil
	data.AdditionalMetadataLocations = nil
	data.RoleDescriptors = nil
	data.SPSSODescriptors = nil

	contactPerson := new(TContactType)
	contactPerson.GivenName = "Alpha"
	contactPerson.SurName = "Beta"
	contactPerson.EmailAddresses = []xsdt.AnyURI{"test@example.com", "second@example.com"}
	contactPerson.TelephoneNumbers = []xsdt.String{"0123456789", "1234567890"}
	contactPerson.ContactType = "technical"
	contactPerson.Extensions = nil
	contactPerson.Company = "ACME"

	data.ContactPersons = []*TContactType{contactPerson}

	data.IDPSSODescriptors = nil

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<EmailAddress xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">second@example.com</EmailAddress>") {
		t.Error(fmt.Errorf("The resulting XML is not correct"))
	}

	result := new(EntityDescriptor)
	err = xml.Unmarshal(xmldata, result)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}
}

func TestUnmarshalEntityDescriptor(t *testing.T) {

	// EntitiesDescriptor represents the SAML object of the same name.
	type EntityDescriptor struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		TEntityDescriptorType
	}

	xmlstr := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2016-11-09T10:39:21.942036958Z" cacheDuration="PT48H" entityID="http://127.0.0.1:8000/metadata">
<IDPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIDMTCCABC</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<KeyDescriptor use="encryption">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIDMTCCAABC</X509Certificate>
</X509Data>
</KeyInfo>
<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>
<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"></EncryptionMethod>
<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"></EncryptionMethod>
<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></EncryptionMethod>
</KeyDescriptor>
<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://127.0.0.1:8000/sso"></SingleSignOnService>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://127.0.0.1:8000/sso"></SingleSignOnService>
</IDPSSODescriptor>
<SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<AssertionConsumerService Binding="binding1" Location="location1" index="1"></AssertionConsumerService>
<AssertionConsumerService Binding="binding2" Location="location2"></AssertionConsumerService>
</SPSSODescriptor>
</EntityDescriptor>`

	data := new(EntityDescriptor)
	err := xml.Unmarshal([]byte(xmlstr), data)
	if err != nil {
		t.Error(fmt.Errorf("An XML Unmarshal error was not expected: %v", err))
	}

	// check AssertionConsumerServices
	acs := data.XElemsSPSSODescriptor.SPSSODescriptors[0].XElemsAssertionConsumerService.AssertionConsumerServices
	assert.Len(t, acs, 2)
	t.Log(acs)
	assert.Equal(t, acs[0].Binding.String(), "binding1")
	assert.Equal(t, acs[0].Location.String(), "location1")
	assert.Equal(t, acs[0].Index.N(), uint16(1))
	assert.Equal(t, acs[1].Binding.String(), "binding2")
	assert.Equal(t, acs[1].Location.String(), "location2")
	assert.Nil(t, acs[1].Index)

	//scsNoPtrAddr := &spew.ConfigState{
	//	Indent:                  "\t",
	//	DisablePointerAddresses: true,
	//	DisableCapacities:       true,
	//}
	//scsNoPtrAddr.Dump(data)

	xmldata, err := xml.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<NameIDFormat xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>") {
		t.Error(fmt.Errorf("The resulting XML is not correct"))
	}
}
