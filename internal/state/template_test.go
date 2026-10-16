package state

import "testing"

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		template string
		kind     Kind
		ok       bool
	}{
		{"", KindJWT, true},
		{"{sub}", KindJWT, true},
		{"ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}", KindJWT, true},
		{"{a}/{b}", KindExec, true},
		{"{member}", KindKeys, true},
		{"fleet/{member}", KindKeys, true},
		{"{sub}", KindKeys, false},
		{"{}", KindJWT, false},
		{"{a//b}", KindJWT, false},
		{"{a", KindJWT, false},
		{"a}", KindJWT, false},
		{"{a}{b}", KindJWT, false},
		{"{{a}}", KindJWT, false},
		{"x{a}", KindJWT, false},
		{"/a", KindJWT, false},
		{"a/", KindJWT, false},
		{"a/./b", KindJWT, false},
	}
	for _, tt := range tests {
		tmpl, err := ParseTemplate(tt.template, tt.kind)
		if (err == nil) != tt.ok {
			t.Errorf("%s template %q: err = %v", tt.kind, tt.template, err)
			continue
		}
		if err == nil && tmpl.String() != tt.template {
			t.Errorf("%q reads back as %q", tt.template, tmpl.String())
		}
	}
}
