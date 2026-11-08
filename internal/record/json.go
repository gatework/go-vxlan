package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON is used only inside domain operations on checked evidence. Invalid
// values fail the operation instead of collapsing into an empty digest/key.
func JSON(value any) []byte {
	body, err := CanonicalJSON(value)
	if err != nil {
		panic(err)
	}
	return body
}

func CanonicalJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, fmt.Errorf("%w: encoding", ErrEvidence)
	}
	encoded := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})

	out := make([]byte, 0, len(encoded))
	for i := 0; i < len(encoded); {
		if encoded[i] != '\\' {
			out = append(out, encoded[i])
			i++
			continue
		}
		start := i
		for i < len(encoded) && encoded[i] == '\\' {
			i++
		}
		count := i - start
		if count%2 == 1 && i+5 <= len(encoded) && (string(encoded[i:i+5]) == "u2028" || string(encoded[i:i+5]) == "u2029") {
			out = append(out, encoded[start:i-1]...)
			if encoded[i+4] == '8' {
				out = append(out, []byte("\u2028")...)
			} else {
				out = append(out, []byte("\u2029")...)
			}
			i += 5
		} else {
			out = append(out, encoded[start:i]...)
		}
	}
	return out, nil
}

// ErrEvidence identifies values that cannot represent unambiguous JSON evidence.
var ErrEvidence = errors.New("vxlan: invalid evidence")
