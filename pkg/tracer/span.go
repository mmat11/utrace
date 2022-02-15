package tracer

import (
	"encoding/json"
)

type span struct {
	Name     string  `json:"name"`
	Value    uint64  `json:"value"`
	Children []*span `json:"children"`
	depth    uint32
	start    uint64
	end      uint64
	isClosed bool
}

func (s *span) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func newSpan(depth uint32, sym string, start uint64) *span {
	return &span{
		Name:     sym,
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

type state struct {
	found bool
	depth uint32
}

func (root *span) exit(sym string, end uint64, st *state) {
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
