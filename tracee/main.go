package main

import "time"

func main() {
	for {
		traceme1(1)
		traceme2(2)
		time.Sleep(time.Second)
	}
}

//go:noinline
func traceme1(a int) {}

//go:noinline
func traceme2(a int) {}
