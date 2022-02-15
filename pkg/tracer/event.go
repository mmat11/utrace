package tracer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type Event struct {
	Kind       string   `json:"kind"`
	Symbol     string   `json:"symbol"`
	Pid        uint32   `json:"pid"`
	Ns         uint64   `json:"ns"`
	Stacktrace []string `json:"stacktrace"`
}

func (e *Event) UnmarshalBinary(t *Tracer, data []byte) error {
	kind := binary.LittleEndian.Uint32(data[0:4])
	switch kind {
	case 0:
		e.Kind = "ENTER"
	case 1:
		e.Kind = "EXIT"
	}
	e.Pid = binary.LittleEndian.Uint32(data[4:8])
	cookie := binary.LittleEndian.Uint64(data[8:16])
	sym, ok := t.refs[cookie]
	if !ok {
		return fmt.Errorf("symbol for cookie %d not found", cookie)
	}
	e.Symbol = sym
	e.Ns = binary.LittleEndian.Uint64(data[16:24])

	e.Stacktrace = make([]string, 0)
	for i := 24; ; i += 8 {
		if len(data) < i+8 {
			break
		}
		off := binary.LittleEndian.Uint64(data[i : i+8])
		if off == 0 {
			continue
		}
		sym, ok := t.syms[off]
		if !ok {
			// miss
			e.Stacktrace = append(e.Stacktrace, fmt.Sprintf("+%#x", off))
			continue
		}
		e.Stacktrace = append(e.Stacktrace, sym)
	}

	return nil
}

func (e *Event) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
