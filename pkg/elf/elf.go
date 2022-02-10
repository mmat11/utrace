package elf

import (
	"debug/elf"
	"errors"
	"fmt"
)

func Symbols(ex string) ([]string, error) {
	syms := make([]string, 0)

	f, err := elf.Open(ex)
	if err != nil {
		return syms, fmt.Errorf("open elf: %w", err)
	}

	load := func(ss []elf.Symbol) {
		for _, s := range ss {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
				continue
			}
			if s.Value == 0 {
				continue
			}
			syms = append(syms, s.Name)
		}
	}

	ss, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return syms, fmt.Errorf("load symbols: %w", err)
	}
	load(ss)

	dss, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return syms, fmt.Errorf("load dynamic symbols: %w", err)
	}
	load(dss)

	return syms, nil
}
