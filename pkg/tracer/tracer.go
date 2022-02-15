package tracer

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mmat11/utrace/pkg/config"
	"github.com/mmat11/utrace/pkg/elf"
)

type Tracer struct {
	executable *link.Executable
	ringbuf    *ringbuf.Reader
	uprobes    []link.Link
	// cookie->sym mapping
	refs map[uint64]string
	// offset->sym mapping
	syms map[uint64]string
	Root span
}

func (t *Tracer) Close() {
	t.ringbuf.Close()

	fmt.Printf("detaching uprobes")
	for i, u := range t.uprobes {
		if i%100 == 0 {
			fmt.Print(".")
		}
		u.Close()
	}
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ../../bpf/utrace.c

func New(c *config.Config) (*Tracer, error) {
	ex, err := link.OpenExecutable(c.Executable)
	if err != nil {
		return nil, err
	}

	syms, err := elf.Symbols(c.Executable)
	if err != nil {
		return nil, err
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	defer objs.Close()

	rb, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		return nil, err
	}

	t := &Tracer{
		executable: ex,
		ringbuf:    rb,
		uprobes:    make([]link.Link, 0),
		refs:       make(map[uint64]string, 0),
		syms:       make(map[uint64]string, 0),
		Root: span{
			Name:     "root",
			Children: make([]*span, 0),
		},
	}

	fmt.Printf("attaching uprobes\n")
	for i, s := range syms {
		cookie := uint64(i)
		t.refs[cookie] = s.Name
		t.syms[s.Enter] = s.Name

		if c.Filter != nil && !c.Filter.MatchString(s.Name) {
			continue
		}

		if len(s.Exit) == 1 && s.Enter == s.Exit[0] {
			fmt.Printf("skipping 1 insn symbol %s\n", s.Name)
			continue
		}

		up, err := ex.Uprobe(
			s.Name,
			objs.UprobeGeneric,
			&link.UprobeOptions{PID: c.Pid, BpfCookie: cookie},
		)
		if err != nil {
			fmt.Printf("could not attach uprobe to symbol %s: %v\n", s.Name, err)
			continue
		}

		t.uprobes = append(t.uprobes, up)

		for _, off := range s.Exit {
			urp, err := ex.Uprobe(
				s.Name,
				objs.UretprobeGeneric,
				&link.UprobeOptions{PID: c.Pid, Offset: off, BpfCookie: cookie},
			)
			if err != nil {
				fmt.Printf("could not attach uprobe to symbol RET address %s(%#x): %v\n", s.Name, off, err)
				continue
			}
			t.uprobes = append(t.uprobes, urp)
		}
	}

	fmt.Printf("attached %d uprobes\n", len(t.uprobes))

	return t, nil
}

func (t *Tracer) Record() error {
	ev := new(Event)
	for {
		record, err := t.ringbuf.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			fmt.Printf("ringbuf read: %v\n", err)
			continue
		}

		if err := ev.UnmarshalBinary(t, record.RawSample); err != nil {
			return fmt.Errorf("unmarshal event: %w", err)
		}

		t.consume(ev)
	}
}

func (t *Tracer) consume(ev *Event) {
	switch ev.Kind {
	case EventKindEnter:
		t.Root.enter(ev.Symbol, ev.Usec)
	case EventKindExit:
		st := exitState{}
		t.Root.exit(ev.Symbol, ev.Usec, &st)
		if !st.found {
			fmt.Printf("received exit event (%s) but no span to close?!\n", ev.Symbol)
			return
		}
		if st.depth == 1 {
			t.Root.refresh()
		}
	}
}
