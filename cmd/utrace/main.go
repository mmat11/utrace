package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/mmat11/utrace/pkg/config"
	"github.com/mmat11/utrace/pkg/tracer"
)

func main() {
	end := make(chan struct{}, 1)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		end <- struct{}{}
	}()

	c := new(config.Config)
	flag.StringVar(&c.Executable, "executable", "", "Path of the executable to trace.")
	flag.IntVar(&c.Pid, "pid", 0, "Pid of the process.")
	flag.Func("filter", "Function filter. Supports regex.", func(r string) error {
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("invalid filter: %w", err)
		}
		c.Filter = re
		return nil
	})
	flag.Parse()

	if err := c.Validate(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	t, err := tracer.New(c)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer t.Close()

	go func() {
		if err := t.Record(); err != nil {
			fmt.Printf("error while recording data: %v", err)
			end <- struct{}{}
		}
	}()

	<-end
}
