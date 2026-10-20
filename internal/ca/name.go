package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"unicode/utf8"
)

var (
	oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// MaxNameLength is the upper bound RFC 5280 sets on an organization and a
// common name.
const MaxNameLength = 64

// Name returns the DER encoding of a distinguished name with an organization
// and a common name, each one UTF8String attribute in its own RDN and either
// left out when empty. Go's own encoder would use PrintableString for the
// values it can, which the specification does not allow where it says
// UTF8String, so names are built here.
func Name(organization, commonName string) ([]byte, error) {
	var rdns pkix.RDNSequence
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{{oidOrganization, organization}, {oidCommonName, commonName}} {
		if a.value == "" {
			continue
		}
		if !utf8.ValidString(a.value) {
			return nil, errors.New("a name attribute is not valid UTF-8")
		}
		raw, err := asn1.MarshalWithParams(a.value, "utf8")
		if err != nil {
			return nil, err
		}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: a.oid, Value: asn1.RawValue{FullBytes: raw}}})
	}
	return asn1.Marshal(rdns)
}
