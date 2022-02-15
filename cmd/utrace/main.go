package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/mmat11/utrace/pkg/config"
	"github.com/mmat11/utrace/pkg/tracer"
)

//go:embed index.html
var index string

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	c := new(config.Config)
	flag.StringVar(&c.Executable, "executable", "", "Path of the executable to trace.")
	flag.IntVar(&c.Pid, "pid", 0, "Pid of the process.")
	flag.BoolVar(&c.SkipRet, "skip-ret", false, "Skip return probes.")
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
			return
		}
	}()

	tp, err := template.New("index").Parse(index)
	if err != nil {
		fmt.Printf("parse template: %v\n", err)
		os.Exit(1)
	}
	http.HandleFunc("/", handleIndex(tp))
	http.HandleFunc("/data.json", handleData(t))

	go func() {
		fmt.Println("listening on http://0.0.0.0:3000")
		http.ListenAndServe(":3000", nil)
	}()

	<-stop
}

func handleIndex(tp *template.Template) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		tp.Execute(w, nil)
	}
}

func handleData(t *tracer.Tracer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		j, _ := json.Marshal(t.Root)
		w.Write(j)
	}
}
