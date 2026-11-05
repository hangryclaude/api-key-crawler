package sweep

import (
	"context"
	"errors"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
)

// Activity is one page of GitHub that is not git and that someone wrote on: an issue, a pull
// request or a release. URL names it exactly, the shape core.APIScanner takes. It is the
// sweep's copy of the shape inventory.Activity has, so that everything else in this package
// is written against these two small interfaces and a fake can stand in for the inventory.
type Activity struct {
	Source string // the repo it belongs to: "github.com/o/r"
	Kind   string // issue|pr|release
	URL    string // https://github.com/o/r/issues/N, /pull/N or /releases/tag/T
	At     string // when GitHub says it was last written, on GitHub's clock
}

// ActivityInventory is an Inventory that names the pages whose text changed, by exact URL. It
// is the inventory's own answer to which comment on which old issue is new, which no cursor
// can say (STEAL P0-22). With one, the events about issues, pull requests and releases are
// already folded into the activity and are not read a second time.
type ActivityInventory interface {
	core.Inventory
	ChangedActivity(ctx context.Context, prev map[string]core.Source) (changed []core.Source, events []core.Event, activity []Activity, err error)
}

// PageLister is an Inventory that can list every issue, pull request and release page of the
// repos it is given, with no cursor: what the weekly deep run reads. The cheap poll can name
// only what changed since it last looked, and a page that changed while nobody was looking
// (a poll that failed, an account whose feed was empty) is found this way.
type PageLister interface {
	ListPages(ctx context.Context, repos []core.Source) ([]Activity, error)
}

// This file is the one place the sweep knows the shape of the real inventory. *inventory.Inventory
// keeps GitHub's clock (Clock) and answers the cheap poll with more than core.Inventory asks
// for (Poll); wrapInventory lets the Runner use both without the wiring code writing glue. An
// inventory that has none of these (a test's fake) comes back as it was.
type (
	poller interface {
		Poll(ctx context.Context, prev map[string]core.Source) (inventory.PollResult, error)
	}
	clocker interface{ Clock() *ghcli.Clock }
	// lister is the method the inventory is asked to grow for the weekly deep run; its shape is
	// the real Activity's.
	lister interface {
		ListPages(ctx context.Context, repos []core.Source) ([]inventory.Activity, error)
	}
)

func wrapInventory(inv core.Inventory) core.Inventory {
	w := live{Inventory: inv}
	w.p, _ = inv.(poller)
	w.c, _ = inv.(clocker)
	w.l, _ = inv.(lister)
	if w.p == nil && w.c == nil && w.l == nil {
		return inv
	}
	return w
}

// live is a core.Inventory with whatever more the one it wraps can do. Its extra methods are
// always there and answer "I cannot" when the wrapped inventory cannot (see namesActivity), so
// one type covers every combination.
type live struct {
	core.Inventory
	p poller
	c clocker
	l lister
}

// namesActivity reports whether ChangedActivity can really name pages, as opposed to being the
// plain cheap poll in the shape of one.
func (w live) namesActivity() bool { return w.p != nil }

// canNameActivity says whether an inventory names the pages that changed.
func canNameActivity(inv core.Inventory) bool {
	if w, ok := inv.(live); ok {
		return w.namesActivity()
	}
	_, ok := inv.(ActivityInventory)
	return ok
}

// canListPages says whether an inventory can list every page of a repo.
func canListPages(inv core.Inventory) bool {
	if w, ok := inv.(live); ok {
		return w.l != nil
	}
	_, ok := inv.(PageLister)
	return ok
}

func (w live) ChangedActivity(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, []Activity, error) {
	if w.p == nil {
		changed, events, err := w.Inventory.Changed(ctx, prev)
		return changed, events, nil, err
	}
	res, err := w.p.Poll(ctx, prev)
	return res.Changed, res.Events, activities(res.Activity), err
}

func activities(in []inventory.Activity) []Activity {
	out := make([]Activity, len(in))
	for i, a := range in {
		out[i] = Activity{Source: a.Source, Kind: a.Kind, URL: a.URL, At: a.At}
	}
	return out
}

func (w live) ServerNow() (time.Time, bool) {
	if w.c == nil {
		return time.Time{}, false
	}
	k := w.c.Clock()
	if k == nil || !k.Known() {
		return time.Time{}, false
	}
	return k.Now(), true
}

// ErrNoPageLister is what ListPages answers when the inventory behind it cannot list pages.
var ErrNoPageLister = errors.New("sweep: the inventory cannot list the pages of a repo")

func (w live) ListPages(ctx context.Context, repos []core.Source) ([]Activity, error) {
	if w.l == nil {
		return nil, ErrNoPageLister
	}
	pages, err := w.l.ListPages(ctx, repos)
	return activities(pages), err
}
