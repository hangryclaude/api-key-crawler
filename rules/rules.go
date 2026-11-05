// Package rules carries rules/keyguard.toml inside the keyguard binary. The installer writes
// it to <root>/rules/ so the engines can be pointed at a file, and an installed binary never
// depends on the source tree it was built from.
package rules

import _ "embed"

// KeyguardTOML is the extra betterleaks/gitleaks rule set, extending the engine defaults.
//
//go:embed keyguard.toml
var KeyguardTOML []byte
