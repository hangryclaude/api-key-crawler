package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// num groups thousands with commas: 41,330 reads faster than 41330.
func num(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return num(n) + " " + many
}

// Run and secret timestamps come from several writers; accept every layout they use
// instead of showing a raw string where one parse would have worked.
var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}

func parseTime(s string, zone *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		if t, err := time.ParseInLocation(l, s, zone); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Month names, not 03/11: a date in digits is read as day-first or month-first depending
// on who reads it, and the user should never have to decide.
func stamp(t time.Time, zone *time.Location) string { return t.In(zone).Format("2 Jan 2006, 15:04") }
func day(t time.Time, zone *time.Location) string   { return t.In(zone).Format("2 Jan 2006") }

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute", "minutes") + " ago"
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours") + " ago"
	case d < 90*24*time.Hour:
		return plural(int(d/(24*time.Hour)), "day", "days") + " ago"
	}
	return plural(int(d/(30*24*time.Hour)), "month", "months") + " ago"
}

// days is the whole number of days between t and now, for the bold number in the First
// seen column. Younger than a day reads "today", not "0 days".
func days(d time.Duration) (n int, word string) {
	n = int(d / (24 * time.Hour))
	switch {
	case d < 0 || n == 0:
		return 0, "today"
	case n == 1:
		return 1, "day"
	}
	return n, "days"
}

func dur(d time.Duration) string {
	switch {
	case d < 0:
		return "—"
	case d < time.Minute:
		if d%time.Second == 0 {
			return fmt.Sprintf("%d s", int(d/time.Second)) // timestamps have whole seconds; ".0" would claim precision
		}
		return secs(d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d min %d s", int(d/time.Minute), int(d%time.Minute/time.Second))
	}
	return fmt.Sprintf("%d h %d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
}

// secs keeps two decimals under 10 s so engine timings like 0.36 s stay comparable.
func secs(f float64) string {
	switch {
	case f < 10:
		return fmt.Sprintf("%.2f s", f)
	case f < 100:
		return fmt.Sprintf("%.1f s", f)
	}
	return fmt.Sprintf("%.0f s", f)
}
