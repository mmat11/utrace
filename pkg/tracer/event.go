package tracer

import "encoding/binary"

type Event struct {
	Kind    uint32
	PidTgid uint64
	Ts      uint64
	Cookie  uint64
}

func (e *Event) UnmarshalBinary(data []byte) error {
	e.Kind = binary.LittleEndian.Uint32(data[0:4])
	e.PidTgid = binary.LittleEndian.Uint64(data[4:12])
	e.Ts = binary.LittleEndian.Uint64(data[12:20])
	e.Cookie = binary.LittleEndian.Uint64(data[20:28])
	return nil
}
