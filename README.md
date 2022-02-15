# utrace

TODO: readme

ulimit -n 50000

```
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

`go run ./cmd/utrace -executable /home/matt/misc/traceme/tracee -filter 'dump.|main.'`

![Screenshot from 2022-02-15 14-02-07](https://user-images.githubusercontent.com/9884419/154067367-df9fc084-8c00-4eae-8a2a-d63613146a5b.png)
