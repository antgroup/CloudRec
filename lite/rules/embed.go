package rules

import "embed"

// FS contains the built-in Lite rule packs and shared rule data.
//
// The CLI still accepts --rules for custom packs, but the bundled rules make the
// default single-binary experience work from any current directory.
//
//go:embed alicloud data mock-public-bucket
var FS embed.FS
