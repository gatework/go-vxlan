package vxlan

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/gatework/go-vxlan/internal/record"
)

// Fingerprint is the Ruby-compatible canonical JSON SHA-256. Maps are sorted;
// arrays retain order and Unicode/HTML characters are not escaped.
func Fingerprint(value any) (string, error) {
	value, err := projectValue(reflect.ValueOf(value), make(map[evidenceVisit]bool), 0)
	if err != nil {
		return "", err
	}
	body, err := record.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(body)), nil
}
