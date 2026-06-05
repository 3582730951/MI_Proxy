package safeexec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CommandSpec struct {
	Name    string
	Args    []string
	Timeout time.Duration
}

var allowedCommands = map[string][][]string{
	"git": {
		{"rev-parse", "--verify", "HEAD"},
		{"branch", "--show-current"},
		{"status", "--short"},
	},
}

func Validate(spec CommandSpec) error {
	if spec.Name == "" {
		return errors.New("command name is required")
	}
	if strings.ContainsAny(spec.Name, `/\`) {
		return fmt.Errorf("command %q must not include a path", spec.Name)
	}
	allowedArgs, ok := allowedCommands[spec.Name]
	if !ok {
		return fmt.Errorf("command %q is not allowlisted", spec.Name)
	}
	for _, candidate := range allowedArgs {
		if equalArgs(candidate, spec.Args) {
			return nil
		}
	}
	return fmt.Errorf("arguments for %q are not allowlisted", spec.Name)
}

func Run(ctx context.Context, spec CommandSpec) (string, error) {
	if err := Validate(spec); err != nil {
		return "", err
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func equalArgs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
