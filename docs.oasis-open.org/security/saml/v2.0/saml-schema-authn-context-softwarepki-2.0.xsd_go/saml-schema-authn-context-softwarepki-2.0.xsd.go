// Package goSamlAuthnContextSoftwarepki20 : autogenerated from XSD schema and manually adjusted (Nicola Asuni - 2016-11-03)
package goSamlAuthnContextSoftwarepki20

import (
	sac "github.com/miracl/go-xsd-pkg/docs.oasis-open.org/security/saml/v2.0/saml-schema-authn-context-2.0.xsd_go"
	sact "github.com/miracl/go-xsd-pkg/docs.oasis-open.org/security/saml/v2.0/saml-schema-authn-context-types-2.0.xsd_go"
	xsdt "github.com/miracl/go-xsd-pkg/xsdt"
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

// TechnicalProtectionBaseType defines type echnicalProtectionBaseType
type TechnicalProtectionBaseType struct {
	*TechnicalProtectionBaseType
	sac.XElemPrivateKeyProtection
}

// Walk : if the WalkHandlers.TechnicalProtectionBaseType function is not nil (ie. was set by outside code), calls it with this TechnicalProtectionBaseType instance as the single argument. Then calls the Walk() method on 1/2 embed(s) and 0/0 field(s) belonging to this TechnicalProtectionBaseType instance.
func (me *TechnicalProtectionBaseType) Walk() (err error) {
	if fn := WalkHandlers.TechnicalProtectionBaseType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TechnicalProtectionBaseType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
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
	sac.XElemAsymmetricKeyAgreement
	sac.XElemsExtension
	*TAuthenticatorBaseType
	sac.XElemDigSig
	sac.XElemAsymmetricDecryption
}

// Walk : if the WalkHandlers.TAuthenticatorBaseType function is not nil (ie. was set by outside code), calls it with this TAuthenticatorBaseType instance as the single argument. Then calls the Walk() method on 1/5 embed(s) and 0/0 field(s) belonging to this TAuthenticatorBaseType instance.
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

// TPrivateKeyProtectionType defines type PrivateKeyProtectionType
type TPrivateKeyProtectionType struct {
	sac.XElemKeyActivation
	sac.XElemKeyStorage
	sac.XElemsExtension
	*TPrivateKeyProtectionType
}

// Walk : if the WalkHandlers.TPrivateKeyProtectionType function is not nil (ie. was set by outside code), calls it with this TPrivateKeyProtectionType instance as the single argument. Then calls the Walk() method on 1/4 embed(s) and 0/0 field(s) belonging to this TPrivateKeyProtectionType instance.
func (me *TPrivateKeyProtectionType) Walk() (err error) {
	if fn := WalkHandlers.TPrivateKeyProtectionType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TPrivateKeyProtectionType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
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

// TKeyActivationType defines type KeyActivationType
type TKeyActivationType struct {
	*TKeyActivationType
	sac.XElemActivationPin
	sac.XElemsExtension
}

// Walk : if the WalkHandlers.TKeyActivationType function is not nil (ie. was set by outside code), calls it with this TKeyActivationType instance as the single argument. Then calls the Walk() method on 1/3 embed(s) and 0/0 field(s) belonging to this TKeyActivationType instance.
func (me *TKeyActivationType) Walk() (err error) {
	if fn := WalkHandlers.TKeyActivationType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TKeyActivationType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
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

// TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium defines type xsdRedefineKeyStorageTypeComplexContentRestrictionMedium
type TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium sac.TmediumType

// IsMemory : Returns true if the value of this enumerated TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium is "memory".
func (me TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium) IsMemory() bool {
	return me.String() == "memory"
}

// Set : Since TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium is just a simple String type, this merely sets the current value from the specified string.
func (me *TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium) Set(s string) {
	(*sac.TmediumType)(me).Set(s)
}

// String : Since TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium is just a simple String type, this merely returns the current string value.
func (me TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium) String() string {
	return sac.TmediumType(me).String()
}

// ToTmediumType : This convenience method just performs a simple type conversion to TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium's alias type sac.TmediumType.
func (me TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium) ToTmediumType() sac.TmediumType {
	return sac.TmediumType(me)
}

// XAttrMediumTxsdRedefineKeyStorageTypeComplexContentRestrictionMedium defines attribute MediumTxsdRedefineKeyStorageTypeComplexContentRestrictionMedium
type XAttrMediumTxsdRedefineKeyStorageTypeComplexContentRestrictionMedium struct {
	Medium TxsdRedefineKeyStorageTypeComplexContentRestrictionMedium `xml:"medium,attr,omitempty"`
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

// TPrincipalAuthenticationMechanismType defines type PrincipalAuthenticationMechanismType
type TPrincipalAuthenticationMechanismType struct {
	*TPrincipalAuthenticationMechanismType
	sac.XElemActivationPin
	sac.XElemsExtension
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

// TKeyStorageType defines type KeyStorageType
type TKeyStorageType struct {
	*TKeyStorageType
	XAttrMediumTxsdRedefineKeyStorageTypeComplexContentRestrictionMedium
}

// Walk : if the WalkHandlers.TKeyStorageType function is not nil (ie. was set by outside code), calls it with this TKeyStorageType instance as the single argument. Then calls the Walk() method on 1/2 embed(s) and 0/0 field(s) belonging to this TKeyStorageType instance.
func (me *TKeyStorageType) Walk() (err error) {
	if fn := WalkHandlers.TKeyStorageType; me != nil {
		if fn != nil {
			if err = fn(me, true); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
				return
			}
		}
		if err = me.TKeyStorageType.Walk(); xsdt.OnWalkError(&err, &WalkErrors, WalkContinueOnError, WalkOnError) {
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

var (
	// WalkContinueOnError can be set to false to break a Walk() immediately as soon as the first error is returned by a custom handler function.
	// If true, Walk() proceeds and accumulates all errors in the WalkErrors slice.
	WalkContinueOnError = true
	// WalkErrors contains all errors accumulated during Walk()s. If you're using this, you need to reset this yourself as needed prior to a fresh Walk().
	WalkErrors []error
	// WalkOnError is your custom error-handling function, if required.
	WalkOnError func(error)
	// WalkHandlers Provides 9 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
	// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
	WalkHandlers = &XWalkHandlers{}
)

// XWalkHandlers Provides 9 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
type XWalkHandlers struct {
	TechnicalProtectionBaseType           func(*TechnicalProtectionBaseType, bool) error
	TAuthenticatorBaseType                func(*TAuthenticatorBaseType, bool) error
	TPrivateKeyProtectionType             func(*TPrivateKeyProtectionType, bool) error
	TPrincipalAuthenticationMechanismType func(*TPrincipalAuthenticationMechanismType, bool) error
	XCdata                                func(*XCdata, bool) error
	TAuthnContextDeclarationBaseType      func(*TAuthnContextDeclarationBaseType, bool) error
	TKeyActivationType                    func(*TKeyActivationType, bool) error
	TAuthnMethodBaseType                  func(*TAuthnMethodBaseType, bool) error
	TKeyStorageType                       func(*TKeyStorageType, bool) error
}
