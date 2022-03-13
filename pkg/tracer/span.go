package tracer

import (
	"fmt"
	"strings"
)

type span struct {
	Name     string  `json:"name"`
	Value    uint64  `json:"value"`
	Children []*span `json:"children,omitempty"`
	depth    uint32
	start    uint64
	end      uint64
	isClosed bool
}

func newSpan(depth uint32, sym string, start uint64) *span {
	return &span{
		Name:     sym,
		Value:    0,
		Children: make([]*span, 0),
		depth:    depth,
		start:    start,
	}
}

func (root *span) enter(sym string, start uint64) {
	for _, s := range root.Children {
		if s.isClosed {
			continue
		}

		s.enter(sym, start)
		return
	}

	ns := newSpan(root.depth+1, sym, start)
	root.Children = append(root.Children, ns)
}

type exitState struct {
	found bool
	depth uint32
}

func (root *span) exit(sym string, end uint64, st *exitState) {
	if st.found {
		return
	}

	for _, s := range root.Children {
		if s.isClosed {
			continue
		}

		s.exit(sym, end, st)
	}

	if root.Name == sym {
		root.end = end
		root.Value = end - root.start
		root.isClosed = true
		st.found = true
		st.depth = root.depth
	}
}

func (root *span) refresh() {
	root.Value = 0
	for _, s := range root.Children {
		if !s.isClosed {
			continue
		}

		root.Value += s.Value
	}
}

func (root *span) Repr(st *strings.Builder) {
	nest := ""
	for i := uint32(0); i < root.depth; i++ {
		nest += "\t"
	}

	_, err := st.WriteString(
		fmt.Sprintf(
			"%s%s[usec=%d, closed=%v]\n", nest, root.Name, root.Value, root.isClosed,
		),
	)
	if err != nil {
		panic(err)
	}

	for _, s := range root.Children {
		s.Repr(st)
	}
}
