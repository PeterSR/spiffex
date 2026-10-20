package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// startTestAgent runs `spiffex agent` for a member of the issuer's state,
// and returns its Workload API address once it serves.
func startTestAgent(t *testing.T, dir, url, clientID, keyFile string) string {
	t.Helper()
	// Socket paths are short, or they do not fit.
	socket := filepath.Join(dir, strings.ReplaceAll(clientID, "/", "-")+".sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, []string{"-issuer", url, "-client-id", clientID, "-key-file", keyFile, "-socket", socket, "-log-level", "error"})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the agent for %s stopped with %v", clientID, err)
		}
	})
	addr := "unix://" + socket
	deadline := time.Now().Add(10 * time.Second)
	for {
		probe, probeCancel := context.WithTimeout(ctx, time.Second)
		_, err := workloadapi.FetchJWTBundles(probe, workloadapi.WithAddr(addr))
		probeCancel()
		if err == nil {
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent for %s did not start: %v", clientID, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Two workloads get X.509-SVIDs from their agents against a running issuer
// and talk mutual TLS authorizing each other by SPIFFE ID; a workload whose
// origin issues JWT-SVIDs only is refused X.509 and keeps its JWT-SVIDs.
func TestAgentsServeX509SVIDsForMutualTLS(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	dir := t.TempDir()

	members := map[string]string{} // client id to key file
	var state strings.Builder
	state.WriteString("origins:\n  dev:\n    provider: keys\n    members:\n")
	jwtOnly := "  batch:\n    provider: keys\n    svid_types: [jwt]\n    members:\n"
	for _, name := range []string{"billing", "orders", "kitchen", "batch"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
		entry := "      " + name + ": { keys: [" + string(pub) + "] }\n"
		origin := "dev"
		if name == "batch" {
			jwtOnly += entry
			origin = "batch"
		} else {
			state.WriteString(entry)
		}
		keyData, err := keyset.MarshalPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		members[origin+"/"+name] = writeFile(t, dir, name+".key", string(keyData))
	}
	writeFile(t, filepath.Dir(config), "state.yaml", state.String()+jwtOnly)
	if _, err := ca.Init(caDir, caTD, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	startTestIssuer(t, config, url)

	addrs := map[string]string{}
	for id, keyFile := range members {
		addrs[id] = startTestAgent(t, dir, url, id, keyFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	source := func(id string) *workloadapi.X509Source {
		t.Helper()
		s, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(addrs[id])))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	billing, orders, kitchen := source("dev/billing"), source("dev/orders"), source("dev/kitchen")
	billingID := spiffeid.RequireFromString("spiffe://example.org/dev/billing")
	ordersID := spiffeid.RequireFromString("spiffe://example.org/dev/orders")
	if svid, err := orders.GetX509SVID(); err != nil || svid.ID != ordersID {
		t.Fatalf("orders was given %v, %v", svid, err)
	}

	// serve answers one connection with the peer's SPIFFE ID, and returns
	// what the server saw.
	type outcome struct {
		peer spiffeid.ID
		err  error
	}
	serve := func(t *testing.T, authorize tlsconfig.Authorizer) (addr string, seen chan outcome) {
		l, err := tls.Listen("tcp", "127.0.0.1:0", tlsconfig.MTLSServerConfig(orders, orders, authorize))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		seen = make(chan outcome, 1)
		go func() {
			conn, err := l.Accept()
			if err != nil {
				seen <- outcome{err: err}
				return
			}
			defer conn.Close()
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				seen <- outcome{err: err}
				return
			}
			peer, err := spiffeIDOf(tlsConn)
			if err == nil {
				_, err = io.WriteString(conn, "hello "+peer.Path())
			}
			seen <- outcome{peer, err}
		}()
		return l.Addr().String(), seen
	}
	dial := func(addr string, src *workloadapi.X509Source, authorize tlsconfig.Authorizer) (string, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsconfig.MTLSClientConfig(src, src, authorize))
		if err != nil {
			return "", err
		}
		defer conn.Close()
		data, err := io.ReadAll(conn)
		return string(data), err
	}

	addr, seen := serve(t, tlsconfig.AuthorizeID(billingID))
	reply, err := dial(addr, billing, tlsconfig.AuthorizeID(ordersID))
	if err != nil || reply != "hello /dev/billing" {
		t.Fatalf("billing to orders: %q, %v", reply, err)
	}
	if got := <-seen; got.err != nil || got.peer != billingID {
		t.Fatalf("the server saw %v, %v", got.peer, got.err)
	}

	// The same handshake the other way round.
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsconfig.MTLSServerConfig(billing, billing, tlsconfig.AuthorizeID(ordersID)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err == nil {
			_, _ = io.WriteString(conn, "billing here")
			conn.Close()
		}
	}()
	if reply, err := dial(l.Addr().String(), orders, tlsconfig.AuthorizeID(billingID)); err != nil || reply != "billing here" {
		t.Fatalf("orders to billing: %q, %v", reply, err)
	}

	// A peer the server does not authorize is turned away, and a server the
	// client does not expect is refused.
	addr, seen = serve(t, tlsconfig.AuthorizeID(billingID))
	if _, err := dial(addr, kitchen, tlsconfig.AuthorizeID(ordersID)); err == nil {
		if got := <-seen; got.err == nil {
			t.Error("kitchen was let in")
		}
	}
	addr, _ = serve(t, tlsconfig.AuthorizeAny())
	if _, err := dial(addr, billing, tlsconfig.AuthorizeID(billingID)); err == nil {
		t.Error("billing accepted a server it did not expect")
	}

	// The origin that issues JWT-SVIDs only: X.509 is refused with
	// PermissionDenied and JWT-SVIDs still flow.
	short, shortCancel := context.WithTimeout(ctx, time.Second)
	defer shortCancel()
	conn, err := grpc.NewClient(addrs["batch/batch"], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api := workload.NewSpiffeWorkloadAPIClient(conn)
	stream, err := api.FetchX509SVID(metadata.AppendToOutgoingContext(short, "workload.spiffe.io", "true"), &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "invalid_target") {
		t.Errorf("X.509 for a JWT-only origin: %v, want PermissionDenied naming invalid_target", err)
	}
	jwt, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"}, workloadapi.WithAddr(addrs["batch/batch"]))
	if err != nil || jwt.ID.String() != "spiffe://example.org/batch/batch" {
		t.Errorf("JWT-SVID for the JWT-only origin: %v, %v", jwt, err)
	}
	// The X.509 bundle is the trust domain's, whatever the workload may ask.
	bundles, err := workloadapi.FetchX509Bundles(ctx, workloadapi.WithAddr(addrs["batch/batch"]))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := bundles.GetX509BundleForTrustDomain(caTD); err != nil || len(b.X509Authorities()) != 1 {
		t.Errorf("X.509 bundle for the JWT-only origin: %v, %v", b, err)
	}
}

func spiffeIDOf(conn *tls.Conn) (spiffeid.ID, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 {
		return spiffeid.ID{}, io.ErrUnexpectedEOF
	}
	return spiffeid.FromURI(state.PeerCertificates[0].URIs[0])
}
