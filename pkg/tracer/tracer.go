package tracer

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mmat11/utrace/pkg/config"
	uelf "github.com/mmat11/utrace/pkg/elf"
)

type Tracer struct {
	executable *link.Executable
	uprobes    []link.Link
	ringbuf    *ringbuf.Reader
	// cookie->sym mapping
	refs map[uint64]string
}

func (t *Tracer) Close() {
	fmt.Println("detaching uprobes")
	for _, u := range t.uprobes {
		u.Close()
	}
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/utrace.c

func New(c *config.Config) (*Tracer, error) {
	ex, err := link.OpenExecutable(c.Executable)
	if err != nil {
		return nil, err
	}

	syms, err := uelf.Symbols(c.Executable)
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
	}
	for i, s := range syms {
		if c.Filter != nil && !c.Filter.MatchString(s) {
			continue
		}

		cookie := uint64(i)

		up, err := ex.Uprobe(s, objs.UprobeGeneric, &link.UprobeOptions{PID: c.Pid, BpfCookie: cookie})
		if err != nil {
			fmt.Printf("could not attach uprobe to symbol %s: %v\n", s, err)
			continue
		}

		// Go binaries will crash!
		// https://github.com/golang/go/issues/22008
		urp, err := ex.Uretprobe(s, objs.UretprobeGeneric, &link.UprobeOptions{PID: c.Pid})
		if err != nil {
			fmt.Printf("could not attach uretprobe to symbol %s: %v\n", s, err)
			continue
		}

		t.uprobes = append(t.uprobes, up)
		t.uprobes = append(t.uprobes, urp)
		t.refs[cookie] = s
	}

	fmt.Printf("attached %d uprobes\n", len(t.uprobes))

	return t, nil
}

func (t *Tracer) Record() error {
	defer t.ringbuf.Close()

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

		fmt.Println(ev.String())
	}
}
