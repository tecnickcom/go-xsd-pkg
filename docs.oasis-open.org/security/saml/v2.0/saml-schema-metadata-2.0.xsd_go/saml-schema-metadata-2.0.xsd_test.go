package goSamlMetadata20

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	xsdt "github.com/miracl/go-xsd-pkg/xsdt"
)

func TestXMLMarshal(t *testing.T) {

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

	//fmt.Printf("\n\n%v\n\n", string(xmldata)) // DEBUG

	if err != nil {
		t.Error(fmt.Errorf("An XML Marshal error was not expected: %v", err))
	}
	if !strings.Contains(string(xmldata), "<EmailAddress xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">second@example.com</EmailAddress>") {
		t.Error(fmt.Errorf("The resulting XML is not correct"))
	}
}
