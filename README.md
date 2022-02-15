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

![Screenshot from 2022-02-15 14-02-07](https://user-images.githubusercontent.com/9884419/154067367-df9fc084-8c00-4eae-8a2a-d63613146a5b.png)
