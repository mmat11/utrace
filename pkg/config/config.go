package config

import (
	"errors"
	"fmt"
	"regexp"
)

type Config struct {
	Executable string
	Pid        int
	Filter     *regexp.Regexp
}

func (c *Config) Validate() error {
	if c.Executable == "" && c.Pid == 0 {
		return errors.New("executable or pid are required")
	}
	if c.Executable == "" {
		c.Executable = fmt.Sprintf("/proc/%d/exe", c.Pid)
	}
	return nil
}
