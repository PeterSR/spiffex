package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// runBootstrap writes the first grant, and usually the origin and member it
// is for, straight to the stored state (SPEC section 8.4). It needs what
// only the operator has: the issuer's settings and access to the storage.
func runBootstrap(ctx context.Context, args []string) error {
	fs := newFlagSet("bootstrap", "-config FILE (-member NAME -key FILE | -who PATTERN) [flags]")
	config := fs.String("config", "", "the issuer's settings file (required), for where the state is and how to validate it")
	origin := fs.String("origin", "operators", "the keys origin the member goes in; created when it does not exist")
	member := fs.String("member", "", "a member to add to the origin, whose SPIFFE ID the grant is for unless -who says otherwise")
	keyFile := fs.String("key", "", "the member's public keys: PEM PUBLIC KEY blocks, or a JWK or JWK Set; - reads standard input")
	grant := fs.String("grant", "operators", "the name of the grant")
	who := fs.String("who", "", "the SPIFFE ID, or SPIFFE ID pattern, the grant is for")
	can := fs.String("can", "read,write,delegate", "the permissions the grant gives, separated by commas")
	var scopes stringList
	fs.Var(&scopes, "on", "a scope of the grant (default /; repeat for several)")
	force := fs.Bool("force", false, "write even though the state has grants already")
	replace := fs.Bool("replace", false, "replace a member or grant of the same name that exists already")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch {
	case *config == "":
		return usageError{errors.New("-config is required")}
	case *member == "" && *who == "":
		return usageError{errors.New("give -member and -key, -who, or both")}
	case (*member == "") != (*keyFile == ""):
		return usageError{errors.New("-member and -key go together")}
	}
	if len(scopes) == 0 {
		scopes = stringList{"/"}
	}

	s, err := settings.Load(*config)
	if err != nil {
		return err
	}
	st, err := store.Open(s.State)
	if err != nil {
		return err
	}
	snap, err := st.Load(ctx)
	if err != nil {
		return fmt.Errorf("reading the state from %s: %w", st, err)
	}
	if snap.Problem != nil {
		return fmt.Errorf("the state in %s does not parse:\n%w", st, snap.Problem)
	}
	next := snap.State
	if len(next.Grants) > 0 && !*force {
		names := slices.Sorted(maps.Keys(next.Grants))
		return fmt.Errorf("the state in %s has grants already (%s): use the management API, or -force to write anyway", st, strings.Join(names, ", "))
	}

	pattern := *who
	var replaced []string
	if o := next.Origins[*origin]; *member != "" && o != nil && o.Members[*member] != nil {
		replaced = append(replaced, fmt.Sprintf("member %s of origin %s", *member, *origin))
	}
	if next.Grants[*grant] != nil {
		replaced = append(replaced, "grant "+*grant)
	}
	if len(replaced) > 0 && !*replace {
		return fmt.Errorf("the state has %s already: use -replace to replace it", strings.Join(replaced, " and "))
	}
	if *member != "" {
		id, err := addMember(next, *origin, *member, *keyFile, s.Validation)
		if err != nil {
			return err
		}
		if pattern == "" {
			pattern = id
		}
	}
	if next.Grants == nil {
		next.Grants = map[string]*state.Grant{}
	}
	perms := splitList(*can)
	next.Grants[*grant] = &state.Grant{Who: pattern, Can: perms, On: scopes}

	if err := state.Validate(next, s.Validation).Err(); err != nil {
		return fmt.Errorf("the state would be invalid; nothing was written:\n%w", err)
	}
	version, err := st.Write(ctx, next, snap.Version)
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("the state in %s changed while it was being written; nothing was written, run again", st)
	}
	if err != nil {
		return err
	}
	for _, r := range replaced {
		fmt.Printf("replaced %s\n", r)
	}
	if *member != "" {
		fmt.Printf("member %s of origin %s is %s\n", *member, *origin, pattern)
	}
	fmt.Printf("grant %s gives %s on %s to %s\n", *grant, strings.Join(perms, ", "), strings.Join(scopes, ", "), pattern)
	fmt.Printf("wrote %s, version %q\n", st, version)
	return nil
}

// addMember puts a member with the keys in keyFile into a keys origin,
// creating the origin when needed, and returns the member's SPIFFE ID.
func addMember(st *state.State, origin, member, keyFile string, s state.Settings) (string, error) {
	var data []byte
	var err error
	if keyFile == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, state.MaxStateSize))
	} else {
		data, err = os.ReadFile(keyFile)
	}
	if err != nil {
		return "", err
	}
	keys, err := store.MemberKeys(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", keyFile, err)
	}
	if st.Origins == nil {
		st.Origins = map[string]*state.Origin{}
	}
	o := st.Origins[origin]
	if o == nil {
		o = &state.Origin{Provider: "keys"}
		st.Origins[origin] = o
	}
	if o.Members == nil {
		o.Members = map[string]*state.Member{}
	}
	o.Members[member] = &state.Member{Keys: keys}
	report := state.ValidateOrigin(origin, o, st.Providers, s)
	if err := report.Err(); err != nil {
		return "", fmt.Errorf("origin %s would be invalid; nothing was written:\n%w", origin, err)
	}
	id, err := report.Origins[origin].MemberID(s.TrustDomain, member)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// splitList splits a list separated by commas, ignoring white space around
// its items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
