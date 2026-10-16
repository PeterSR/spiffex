// Package schema holds the JSON Schemas (draft 2020-12) of the state
// document, a provider and an origin (SPEC section 6.3).
package schema

import "embed"

// FS holds state.schema.json, provider.schema.json and origin.schema.json.
//
//go:embed *.json
var FS embed.FS

// The schemas' stable identifiers.
const (
	StateID    = "https://github.com/PeterSR/spiffex/schema/state.schema.json"
	ProviderID = "https://github.com/PeterSR/spiffex/schema/provider.schema.json"
	OriginID   = "https://github.com/PeterSR/spiffex/schema/origin.schema.json"
)
