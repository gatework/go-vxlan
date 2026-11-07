package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDocumentNumbersPreserveEvidence(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"9007199254740993", "9007199254740993"},
		{"18446744073709551616", "18446744073709551616"},
		{"1.00000000000000000001", "1.00000000000000000001"},
		{"2.0", "2"}, {"2e0", "2"}, {"0.2e1", "2"},
		{"1e999999", "1e999999"}, {"1e-999999", "1e-999999"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			doc, e := decodeDocument([]byte(`{"n":` + tc.input + `}`))
			if e != nil {
				t.Fatal(e)
			}
			b, e := json.Marshal(doc)
			if e != nil || string(b) != `{"n":`+tc.want+`}` {
				t.Fatalf("%s %v", b, e)
			}
			again, e := decodeDocument(b)
			if e != nil || !reflect.DeepEqual(doc, again) {
				t.Fatal("unstable roundtrip", e)
			}
		})
	}
}
func TestDocumentRejectsAmbiguousOrMalformedInput(t *testing.T) {
	for _, body := range []string{
		`{"a":null,"a":1}`, `{"a":[{"x":1,"\u0078":2}]}`,
		`[]`, `null`, `{"a":1} {}`, `{"a":[1}}`, `{"a":true,}`, "{\"a\":\"\xff\"}",
		`{"a":` + strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130) + "}",
	} {
		if _, e := decodeDocument([]byte(body)); e == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	doc, e := decodeDocument([]byte(`{"a":[{"x":1},{"x":2}],"empty":[]}`))
	if e != nil || len(doc) != 2 {
		t.Fatal("valid independent keys rejected", e)
	}
}
func TestACLSequenceIntegerBoundaries(t *testing.T) {
	for _, sequence := range []string{"1", "4294967295", "1.0", "1e0", "1.00000000000000001"} {
		doc, e := decodeDocument([]byte(`{"acls":{"WEB":[{"action":"permit","sequence":` + sequence + `,"expression":"ip any any"}]}}`))
		if e != nil {
			t.Fatal(e)
		}
		e = validateConfigurationRecord(doc)
		if sequence == "1.00000000000000001" {
			if e == nil {
				t.Fatal("rounded fractional identity accepted")
			}
		} else if e != nil {
			t.Fatal(sequence, e)
		}
	}
}
func FuzzEvidenceDocument(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1}`, `{"a":null,"a":2}`, `{"a":9007199254740993}`, `{"a":[true,null,"x"]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		doc, e := decodeDocument([]byte(s))
		if e != nil {
			return
		}
		if !json.Valid([]byte(s)) {
			t.Fatal("accepted invalid JSON")
		}
		b, e := json.Marshal(doc)
		if e != nil {
			t.Fatal(e)
		}
		again, e := decodeDocument(b)
		if e != nil || !reflect.DeepEqual(doc, again) {
			t.Fatal("unstable document roundtrip", e)
		}
	})
}
