package guard

import (
	"os"
	"testing"
)

// The guard loads the learned-secret store of the real data root unless it is told otherwise.
// A test must never read the user's, so the whole process runs under a home of its own, and
// KEYGUARD_HOME names nothing.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "guard-test-home-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Unsetenv("KEYGUARD_HOME")
	code := m.Run()
	os.RemoveAll(home) // this process made it, and holds nothing of anyone's
	os.Exit(code)
}
