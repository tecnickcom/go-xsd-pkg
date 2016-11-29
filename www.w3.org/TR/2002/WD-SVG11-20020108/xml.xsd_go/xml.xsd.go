// Package goXml : autogenerated from XSD schema and manually adjusted (Nicola Asuni - 2016-11-03)
package goXml

import (
	xsdt "github.com/miracl/go-xsd-pkg/xsdt"
)

// XAttrLang The content of the lang attribute is a hyphen-separated list of case-insensitive tokens where the first token, if one character, is "i" or "x"; if two characters, is an ISO 639-1 language code; if three characters, is an ISO 639-2 language code. The second token, if two characters, is an ISO 3166-1 country code; if from three to eight characters, is an IANA-registered language code. The meaning of other tokens is undefined. This documentation briefly summarizes  RFC3066, which obseletes RFC1766.
// Examples: en-GB ja-JP no-bok sgn-US i-navajo cel-gaulish
// XML specification, Language Identification (in the second edition as modified by errattum E11)
// RFC 3066
// Registration authority for ISO 639-1 and -2
// Registration authority for ISO 3166
// IANA-registered language codes
type XAttrLang struct {
	//	The content of the lang attribute is a hyphen-separated list of case-insensitive tokens where the first token, if one character, is "i" or "x"; if two characters, is an ISO 639-1 language code; if three characters, is an ISO 639-2 language code. The second token, if two characters, is an ISO 3166-1 country code; if from three to eight characters, is an IANA-registered language code. The meaning of other tokens is undefined. This documentation briefly summarizes  RFC3066, which obseletes RFC1766.
	//	Examples: en-GB ja-JP no-bok sgn-US i-navajo cel-gaulish
	//	XML specification, Language Identification (in the second edition as modified by errattum E11)
	//	RFC 3066
	//	Registration authority for ISO 639-1 and -2
	//	Registration authority for ISO 3166
	//	IANA-registered language codes
	Lang xsdt.Nmtoken `xml:"lang,attr,omitempty"`
}

// TxsdSpace defines type xsdSpace
type TxsdSpace xsdt.String

// Set : Since TxsdSpace is just a simple String type, this merely sets the current value from the specified string.
func (me *TxsdSpace) Set(s string) { (*xsdt.String)(me).Set(s) }

// String : Since TxsdSpace is just a simple String type, this merely returns the current string value.
func (me TxsdSpace) String() string { return xsdt.String(me).String() }

// ToXsdtString : This convenience method just performs a simple type conversion to TxsdSpace's alias type xsdt.String.
func (me TxsdSpace) ToXsdtString() xsdt.String { return xsdt.String(me) }

// IsDefault : Returns true if the value of this enumerated TxsdSpace is "default".
func (me TxsdSpace) IsDefault() bool { return me.String() == "default" }

// IsPreserve : Returns true if the value of this enumerated TxsdSpace is "preserve".
func (me TxsdSpace) IsPreserve() bool { return me.String() == "preserve" }

// XAttrSpace defines attribute Space
type XAttrSpace struct {
	Space TxsdSpace `xml:"space,attr,omitempty"`
}

// XAttrBase defines attribute Base
type XAttrBase struct {
	Base xsdt.AnyURI `xml:"base,attr,omitempty"`
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
	// WalkHandlers Provides 1 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
	// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
	WalkHandlers = &XWalkHandlers{}
)

// XWalkHandlers Provides 1 strong-typed hooks for your own custom handler functions to be invoked when the Walk() method is called on any instance of any (non-attribute-related) struct type defined in this package.
// If your custom handler does get called at all for a given struct instance, then it always gets called twice, first with the 'enter' bool argument set to true, then (after having Walk()ed all subordinate struct instances, if any) once again with it set to false.
type XWalkHandlers struct {
	XCdata func(*XCdata, bool) error
}
