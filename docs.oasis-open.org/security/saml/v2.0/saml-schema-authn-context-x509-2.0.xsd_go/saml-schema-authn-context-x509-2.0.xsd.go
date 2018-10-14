// Package goSamlAuthnContextX50920 : autogenerated from XSD schema and manually adjusted (Nicola Asuni - 2016-11-03)
package goSamlAuthnContextX50920

import (
	sac "github.com/tecnickcom/go-xsd-pkg/docs.oasis-open.org/security/saml/v2.0/saml-schema-authn-context-2.0.xsd_go"
	sact "github.com/tecnickcom/go-xsd-pkg/docs.oasis-open.org/security/saml/v2.0/saml-schema-authn-context-types-2.0.xsd_go"
	xsdt "github.com/tecnickcom/go-xsd-pkg/xsdt"
)

// XAttrIDXsdtID defines attribute Id
type XAttrIDXsdtID struct {
	ID xsdt.ID `xml:"ID,attr,omitempty"`
}

// TAuthnContextDeclarationBaseType defines type AuthnContextDeclarationBaseType
type TAuthnContextDeclarationBaseType struct {
	sac.XElemAuthnMethod
	sac.XElemGoverningAgreements
	sac.XElemsExtension
	XAttrIDXsdtID
	*TAuthnContextDeclarationBaseType
	sac.XElemIdentification
	sact.XElemTechnicalProtection
	sac.XElemOperationalProtection
}

// Walk : if the WalkHandlers.TAuthnContextDeclarationBaseType function is not nil (ie. was set by outside code), calls it with this TAuthnContextDeclarationBaseType instance as the single argument. Then calls the Walk() method on 1/8 embed(s) and 0/0 field(s) belonging to this TAuthnContextDeclarationBaseType instance.
func (me *TAuthnContextDeclarationBaseType) Walk() (err error) {
	if fn := WalkHandlers.TAuthnContextDeclarationBaseType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TAuthnContextDeclarationBaseType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
			return
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

// XAttrPreauthXsdtInteger defines attribute Preauth
type XAttrPreauthXsdtInteger struct {
	Preauth xsdt.Integer `xml:"preauth,attr,omitempty"`
}

// TPrincipalAuthenticationMechanismType defines type PrincipalAuthenticationMechanismType
type TPrincipalAuthenticationMechanismType struct {
	*TPrincipalAuthenticationMechanismType
	sac.XElemRestrictedPassword
	XAttrPreauthXsdtInteger
}

// Walk : if the WalkHandlers.TPrincipalAuthenticationMechanismType function is not nil (ie. was set by outside code), calls it with this TPrincipalAuthenticationMechanismType instance as the single argument. Then calls the Walk() method on 1/3 embed(s) and 0/0 field(s) belonging to this TPrincipalAuthenticationMechanismType instance.
func (me *TPrincipalAuthenticationMechanismType) Walk() (err error) {
	if fn := WalkHandlers.TPrincipalAuthenticationMechanismType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TPrincipalAuthenticationMechanismType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
			return
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

// XAttrKeyValidationXsdtAnyURIUrnOasisNamesTcSaml20AcClassesX509 defines attribute KeyValidation
type XAttrKeyValidationXsdtAnyURIUrnOasisNamesTcSaml20AcClassesX509 struct {
	KeyValidation xsdt.AnyURI `xml:"keyValidation,attr,omitempty"`
}

// KeyValidationFixed : Returns the fixed value for KeyValidation -- "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
func (me XAttrKeyValidationXsdtAnyURIUrnOasisNamesTcSaml20AcClassesX509) KeyValidationFixed() xsdt.AnyURI {
	return xsdt.AnyURI("urn:oasis:names:tc:SAML:2.0:ac:classes:X509")
}

// XCdata defines type CDATA
type XCdata struct {
	XCDATA string `xml:",chardata"`
}

// Walk : if the WalkHandlers.XCdata function is not nil (ie. was set by outside code), calls it with this XCdata instance as the single argument. Then calls the Walk() method on 0/0 embed(s) and 0/1 field(s) belonging to this XCdata instance.
func (me *XCdata) Walk() (err error) {
	if fn := WalkHandlers.XCdata; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

// TPublicKeyType defines type PublicKeyType
type TPublicKeyType struct {
	*TPublicKeyType
	XAttrKeyValidationXsdtAnyURIUrnOasisNamesTcSaml20AcClassesX509
}

// Walk : if the WalkHandlers.TPublicKeyType function is not nil (ie. was set by outside code), calls it with this TPublicKeyType instance as the single argument. Then calls the Walk() method on 1/2 embed(s) and 0/0 field(s) belonging to this TPublicKeyType instance.
func (me *TPublicKeyType) Walk() (err error) {
	if fn := WalkHandlers.TPublicKeyType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TPublicKeyType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
			return
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

// TAuthnMethodBaseType defines type AuthnMethodBaseType
type TAuthnMethodBaseType struct {
	sac.XElemAuthenticatorTransportProtocol
	sac.XElemsExtension
	*TAuthnMethodBaseType
	sac.XElemPrincipalAuthenticationMechanism
	sac.XElemAuthenticator
}

// Walk : if the WalkHandlers.TAuthnMethodBaseType function is not nil (ie. was set by outside code), calls it with this TAuthnMethodBaseType instance as the single argument. Then calls the Walk() method on 1/5 embed(s) and 0/0 field(s) belonging to this TAuthnMethodBaseType instance.
func (me *TAuthnMethodBaseType) Walk() (err error) {
	if fn := WalkHandlers.TAuthnMethodBaseType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TAuthnMethodBaseType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
			return
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

// TAuthenticatorBaseType defines type AuthenticatorBaseType
type TAuthenticatorBaseType struct {
	*TAuthenticatorBaseType
	sac.XElemDigSig
}

// Walk : if the WalkHandlers.TAuthenticatorBaseType function is not nil (ie. was set by outside code), calls it with this TAuthenticatorBaseType instance as the single argument. Then calls the Walk() method on 1/2 embed(s) and 0/0 field(s) belonging to this TAuthenticatorBaseType instance.
func (me *TAuthenticatorBaseType) Walk() (err error) {
	if fn := WalkHandlers.TAuthenticatorBaseType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TAuthenticatorBaseType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
			return
		}
		if fn != nil {
			if err = fn(me, false); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
	}
	return
}

var (
	// WalkContinueOnError can be set to false to break a Walk() immediately as soon as the first error is returned by a custom handler function.
	// If true, Walk() proceeds and accumulates all errors in the WalkErrors slice.
	WalkContinueOnError = true
	// WalkErrors contains all errors accumulated during Walk()s. If you're using this, you need to reset this yourself as needed prior to a fresh Walk().
	WalkErrors []error
	// WalkOnError is your custom error-handling function, if required.
	WalkOnError func(error)
	// WalkHandlers Provides 6 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
	// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
	WalkHandlers = &XWalkHandlers{}
)

// XWalkHandlers Provides 6 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
type XWalkHandlers struct {
	TAuthnContextDeclarationBaseType      func(*TAuthnContextDeclarationBaseType, bool) error
	TPrincipalAuthenticationMechanismType func(*TPrincipalAuthenticationMechanismType, bool) error
	XCdata                                func(*XCdata, bool) error
	TPublicKeyType                        func(*TPublicKeyType, bool) error
	TAuthnMethodBaseType                  func(*TAuthnMethodBaseType, bool) error
	TAuthenticatorBaseType                func(*TAuthenticatorBaseType, bool) error
}
