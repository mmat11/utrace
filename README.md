# utrace

TODO: readme

![Screenshot from 2022-02-16 20-27-47](https://user-images.githubusercontent.com/9884419/154341732-d8e1b746-4922-4bd9-b813-4b7b5f1cbf73.png)

```
~ ulimit -n 50000
~ go run ./cmd/utrace -executable /home/matt/misc/traceme/tracee -filter 'dump.|main.

package main

import (
	"time"

	"github.com/davecgh/go-spew/spew"
)

type asdf struct {
	a, b, c int
}

func main() {
	a := traceme(1, 2, 3)
	spew.Dump(a)
}

func traceme(a, b, c int) asdf {
	time.Sleep(50 * time.Microsecond)
	abc := asdf{a, b, c}
	spew.Dump(abc)
	abc.a = 13
	abc.b = 3
	abc.c = 7
	return abc
}
```
