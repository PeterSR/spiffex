// Command goclient is the go-spiffe side of the conformance matrix. It uses
// only stock go-spiffe APIs, the way a workload or verifier would.
//
//	goclient fetch AUDIENCE                         JWT-SVID from SPIFFE_ENDPOINT_SOCKET
//	goclient validate-agent AUDIENCE TOKEN          ValidateJWTSVID through the agent
//	goclient validate-source AUDIENCE TOKEN         against a JWTSource's bundle
//	goclient validate-bundle URL TD AUDIENCE TOKEN  against the issuer's bundle endpoint
//
// It exits 3 when a token is refused, and 1 on any other failure, so a test
// can tell a refusal from a verifier that is down.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// refused marks an error as the token being refused.
type refused struct{ error }

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "goclient:", err)
		if errors.As(err, new(refused)) {
			os.Exit(3)
		}
		os.Exit(1)
	}
	fmt.Println(out)
}

func run(ctx context.Context, args []string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == "fetch":
		source, err := workloadapi.NewJWTSource(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: args[1]})
		if err != nil {
			return "", err
		}
		return svid.Marshal(), nil

	case len(args) == 3 && args[0] == "validate-agent":
		client, err := workloadapi.New(ctx)
		if err != nil {
			return "", err
		}
		defer client.Close()
		svid, err := client.ValidateJWTSVID(ctx, args[2], args[1])
		if status.Code(err) == codes.InvalidArgument {
			return "", refused{err}
		}
		if err != nil {
			return "", err
		}
		return svid.ID.String(), nil

	case len(args) == 3 && args[0] == "validate-source":
		source, err := workloadapi.NewJWTSource(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		svid, err := jwtsvid.ParseAndValidate(args[2], source, []string{args[1]})
		if err != nil {
			return "", refused{err}
		}
		return svid.ID.String(), nil

	case len(args) == 5 && args[0] == "validate-bundle":
		td, err := spiffeid.TrustDomainFromString(args[2])
		if err != nil {
			return "", err
		}
		bundle, err := federation.FetchBundle(ctx, td, args[1])
		if err != nil {
			return "", err
		}
		svid, err := jwtsvid.ParseAndValidate(args[4], bundle, []string{args[3]})
		if err != nil {
			return "", refused{err}
		}
		return svid.ID.String(), nil
	}
	return "", fmt.Errorf("bad arguments %q", args)
}
