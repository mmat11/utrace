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

	fmt.Println("detaching uprobes")
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
	for i, s := range syms {
		t.syms[s.Value] = s.Name

		if c.Filter != nil && !c.Filter.MatchString(s.Name) {
			continue
		}

		cookie := uint64(i)

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
		t.refs[cookie] = s.Name

		if c.SkipRet {
			continue
		}
		// Go binaries will crash!
		// https://github.com/golang/go/issues/22008
		urp, err := ex.Uretprobe(
			s.Name,
			objs.UretprobeGeneric,
			&link.UprobeOptions{PID: c.Pid, BpfCookie: cookie},
		)
		if err != nil {
			fmt.Printf("could not attach uretprobe to symbol %s: %v\n", s.Name, err)
			continue
		}

		t.uprobes = append(t.uprobes, urp)
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

		switch ev.Kind {
		case "ENTER":
			t.Root.enter(ev.Symbol, ev.Ns)
		case "EXIT":
			st := state{}
			t.Root.exit(ev.Symbol, ev.Ns, &st)
			if !st.found {
				// ???
				fmt.Println("no enter event found for", ev.Symbol)
				continue
			}
			if st.depth == 1 {
				t.Root.Value = 0
				for _, c := range t.Root.Children {
					t.Root.Value += c.Value
				}
				fmt.Println(t.Root.String())
			}
		}
	}
}
