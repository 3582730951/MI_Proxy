package safeexec

import (
	"testing"
	"time"
)

func TestValidateAllowsOnlyStructuredGitProvenanceCommands(t *testing.T) {
	allowed := []CommandSpec{
		{Name: "git", Args: []string{"rev-parse", "--verify", "HEAD"}},
		{Name: "git", Args: []string{"branch", "--show-current"}, Timeout: time.Second},
		{Name: "git", Args: []string{"status", "--short"}},
	}
	for _, spec := range allowed {
		if err := Validate(spec); err != nil {
			t.Fatalf("allowed command rejected: %+v err=%v", spec, err)
		}
	}

	blocked := []CommandSpec{
		{Name: "bash", Args: []string{"-c", "git status"}},
		{Name: "powershell", Args: []string{"-Command", "git status"}},
		{Name: "git", Args: []string{"status", "--short", "--untracked-files=all"}},
		{Name: "git", Args: []string{"push"}},
		{Name: "../git", Args: []string{"status", "--short"}},
	}
	for _, spec := range blocked {
		if err := Validate(spec); err == nil {
			t.Fatalf("unsafe command accepted: %+v", spec)
		}
	}
}
