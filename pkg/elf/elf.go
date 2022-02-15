package elf

import (
	"debug/elf"
	"errors"
	"fmt"
)

type Sym struct {
	Name  string
	Value uint64
}

func Symbols(ex string) ([]Sym, error) {
	ss := make([]Sym, 0)

	f, err := elf.Open(ex)
	if err != nil {
		return nil, fmt.Errorf("open elf: %w", err)
	}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	syms = append(syms, dynsyms...)

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if s.Value == 0 {
			continue
		}
		ss = append(ss, Sym{s.Name, s.Value})
	}

	return ss, nil
}
