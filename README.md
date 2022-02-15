# utrace

TODO: readme


```
package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
)

func init() {
	fmt.Println("INIT")
}

type asdf struct {
	a, b, c int
}

func main() {
	a := traceme(1, 2, 3)
	spew.Dump(a)
	fmt.Println("DONE")
}

//go:noinline
func traceme(a, b, c int) asdf {
	return asdf{a, b, c}
}
```

`go run ./cmd/utrace -executable /home/matt/misc/traceme/tracee -filter 'dump.|main.'`

