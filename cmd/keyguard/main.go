// Command keyguard keeps the user's API keys off GitHub: it blocks them at commit, push and
// publish time, finds the ones that already got out, and watches GitHub every minute.
// This file is only the dispatcher; the work is in internal/, wired together here and in
// the cmd_*.go files beside it.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx := context.Background()
	stop := func() {}
	// A scan has children (git, engines) that run in their own process group, so Ctrl-C only
	// reaches them if this process passes the cancellation down. The hooks and the guard are
	// the opposite: a signal should kill them as it always did, not be swallowed into a
	// "scan cancelled, allow" that git would read as a pass.
	if len(os.Args) > 1 && os.Args[1] != "hook" && os.Args[1] != "guard" {
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
