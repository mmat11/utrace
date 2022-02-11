package tracer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type Event struct {
	PidTgid uint64 `json:"pid_tgid"`
	Kind    string `json:"kind"`
	Ts      uint64 `json:"timestamp"`
	Symbol  string `json:"symbol"`
}

func (e *Event) UnmarshalBinary(t *Tracer, data []byte) error {
	kind := binary.LittleEndian.Uint32(data[0:4])
	switch kind {
	case 1:
		e.Kind = "ENTRY"
	case 2:
		e.Kind = "EXIT"
	default:
		e.Kind = "n/a"
	}

	e.PidTgid = binary.LittleEndian.Uint64(data[4:12])
	e.Ts = binary.LittleEndian.Uint64(data[12:20])

	cookie := binary.LittleEndian.Uint64(data[20:28])
	sym, ok := t.refs[cookie]
	if !ok {
		return fmt.Errorf("symbol for cookie %d not found", cookie)
	}
	e.Symbol = sym

	return nil
}

func (e *Event) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
