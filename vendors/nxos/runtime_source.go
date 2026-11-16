package nxos

import (
	"strings"
)

// runtimeLine binds a command's logical row to its original physical lines.
// Only command-specific wrapped rows change text; source numbering never changes.
type runtimeLine struct {
	text        string
	first, last int
}

type runtimeText []runtimeLine

func newRuntimeText(text string) (runtimeText, error) {
	content, err := newTextContent(text)
	if err != nil {
		return nil, err
	}
	lines := make(runtimeText, 0, content.Len())
	for line := range content.All() {
		lines = append(lines, runtimeLine{text: line.Text, first: line.Number, last: line.Number})
	}
	return lines, nil
}

func rtNormalizeWrapped(name string, lines runtimeText) runtimeText {
	if name != "nve_peers" && name != "bgp_neighbors" {
		return lines
	}
	out := make(runtimeText, 0, len(lines))
	for _, line := range lines {
		tail := rtTrim(line.text)
		prev := ""
		if len(out) > 0 {
			prev = rtTrim(out[len(out)-1].text)
		}
		join := strings.HasSuffix(prev, "State/") && tail == "PfxRcd"
		if name == "nve_peers" {
			wrappedHeader := strings.HasSuffix(prev, "Route") && tail == "r-Mac"
			wrappedMAC := rtMatch(`(?i)^[\da-f]{4}\.[\da-f]{4}$`, tail) &&
				rtMatch(`(?i)^nve\d+\s+\d+(?:\.\d+){3}\s+(?:Up|Down)\s+\S+\s+\S+\s+[\da-f]{4}\.$`, prev)
			join = wrappedHeader || wrappedMAC
		}
		if join {
			previous := &out[len(out)-1]
			previous.text = strings.TrimRight(previous.text, " \t\r\n") + tail
			previous.last = line.last
			continue
		}
		out = append(out, line)
	}
	return out
}

func rtScopeBlocks(name string, lines runtimeText) []runtimeText {
	boundary := "BGP summary information for VRF "
	switch name {
	case "bgp_neighbors":
	case "ospf_neighbors":
		boundary = "OSPF Process ID "
	default:
		return nil
	}
	blocks := []runtimeText{}
	start := 0
	hasText := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line.text, " \t\r\n"), boundary) && i > start {
			if hasText {
				blocks = append(blocks, lines[start:i])
			}
			start = i
			hasText = false
		}
		hasText = hasText || rtTrim(line.text) != ""
	}
	if hasText {
		blocks = append(blocks, lines[start:])
	}
	return blocks
}
