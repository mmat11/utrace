package elf

import (
	"debug/elf"
	"errors"
	"fmt"
	"go/build"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type Sym struct {
	Name  string
	Enter uint64
	Exit  []uint64
}

func (s Sym) String() string {
	repr := fmt.Sprintf("%s - %#x - ", s.Name, s.Enter)
	for _, e := range s.Exit {
		repr += fmt.Sprintf("%#x ", e)
	}
	return repr
}

func Symbols(ex string) ([]Sym, error) {
	ss := make([]Sym, 0)

	f, err := elf.Open(ex)
	if err != nil {
		return ss, fmt.Errorf("open elf: %w", err)
	}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ss, err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ss, err
	}

	syms = append(syms, dynsyms...)

	// data, err := f.Section(".text").Data()
	// if err != nil {
	// 	return ss, err
	// }
	//
	// eng, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	// if err != nil {
	// 	return ss, err
	// }
	// defer eng.Close()

	rets, err := readRets(f, ex)
	if err != nil {
		return ss, err
	}

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if s.Value == 0 || s.Size == 0 {
			continue
		}

		sym := Sym{
			Name:  s.Name,
			Enter: s.Value,
			Exit:  make([]uint64, 0),
		}

		// insns, err := eng.Disasm(data, addrToOffset(f, s.Value), s.Size)
		// if err != nil {
		// 	return ss, err
		// }
		//
		// for _, insn := range insns {
		// 	// fmt.Printf("%#x %s %s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		// 	if insn.Mnemonic == "ret" {
		// 		sym.Exit = append(sym.Exit, uint64(insn.Address))
		// 	}
		// }

		offs, ok := rets[s.Name]
		if !ok {
			fmt.Printf("WARNING: %s RET address not found\n", s.Name)
		}
		sym.Exit = append(sym.Exit, offs...)

		ss = append(ss, sym)
	}

	return ss, nil
}

func addrToOffset(f *elf.File, addr uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off
		}
	}
	return addr
}

// https://github.com/iovisor/bcc/issues/1320#issuecomment-407927542
func readRets(f *elf.File, ex string) (map[string][]uint64, error) {
	r := make(map[string][]uint64, 0)

	// TODO: this is ugly and slow, find a better way
	out, err := exec.Command(
		path.Join(build.Default.GOROOT, "bin/go"), "tool", "objdump", ex,
	).Output()
	if err != nil {
		return r, err
	}

	re := regexp.MustCompile(`\s+`)
	polish := func(s string) []string {
		s = strings.ReplaceAll(s, "\t", " ")
		s = re.ReplaceAllString(s, " ")
		s = strings.Trim(s, " ")
		return strings.Split(s, " ")
	}

	var currentSym string
	insns := strings.Split(string(out), "\n")
	for _, i := range insns {
		insn := polish(i)

		if insn[0] == "TEXT" {
			symStr := strings.Join(insn[1:len(insn)-1], " ")
			currentSym = strings.ReplaceAll(symStr, "(SB)", "")
			r[currentSym] = make([]uint64, 0)
			continue
		}

		if len(insn) == 4 && insn[3] == "RET" {
			addrStr := strings.Replace(insn[1], "0x", "", 1)
			addr, _ := strconv.ParseUint(addrStr, 16, 64)
			r[currentSym] = append(r[currentSym], addrToOffset(f, addr))
		}
	}

	return r, nil
}
