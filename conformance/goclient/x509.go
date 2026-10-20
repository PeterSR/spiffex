package main

// The X.509 side of the go-spiffe client:
//
//	goclient x509-fetch DIR                       write the agent's X.509-SVID to DIR/key.pem and DIR/chain.pem
//	goclient x509-bundle FILE                     write the agent's X.509 authorities to FILE
//	goclient x509-verify CHAINFILE                x509svid.Verify against the agent's bundle
//	goclient x509-serve ADDRFILE [LISTEN]         mTLS server with the agent's SVID and bundle
//	goclient x509-serve-files ADDRFILE KEY CHAIN BUNDLE TD
//	                                              the same with an SVID and a bundle read from files
//	goclient x509-dial ADDR TD                    mTLS client with the agent's SVID and bundle
//	goclient x509-dial-files ADDR KEY CHAIN BUNDLE TD
//	goclient x509-dial-anon ADDR BUNDLE TD        a client that sends no certificate
//	goclient x509-hold ADDR TD COUNT              one connection, COUNT lines a second apart
//
// Servers write their address to ADDRFILE once they listen (on LISTEN, by
// default an ephemeral port of the loopback), authorize every member of the
// trust domain and answer each line of a connection with "server=ID
// client=ID client_ca=KEY". Dial sends one line and prints the answer and
// "server_ca=KEY peer=ID", the key identifier of the CA that signed the
// server's certificate and the ID the client itself read from it. Hold prints a time and the answer for each line and fails when
// the connection does. A dial that gets as far as a
// TCP connection and then fails is a refusal (exit 3): TLS 1.3 tells a client
// that the server refused its certificate only on the first read.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func runX509(ctx context.Context, args []string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == "x509-fetch":
		// One call, not a source: a source retries a refusal until its deadline.
		x509Context, err := workloadapi.FetchX509Context(ctx)
		if err != nil {
			return "", err
		}
		svid := x509Context.DefaultSVID()
		chain, key, err := svid.Marshal()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(args[1], 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(args[1], "key.pem"), key, 0o600); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(args[1], "chain.pem"), chain, 0o644); err != nil {
			return "", err
		}
		return svid.ID.String(), nil

	case len(args) == 2 && args[0] == "x509-bundle":
		x509Context, err := workloadapi.FetchX509Context(ctx)
		if err != nil {
			return "", err
		}
		bundle, err := x509Context.Bundles.GetX509BundleForTrustDomain(x509Context.DefaultSVID().ID.TrustDomain())
		if err != nil {
			return "", err
		}
		pem, err := bundle.Marshal()
		if err != nil {
			return "", err
		}
		return "", os.WriteFile(args[1], pem, 0o644)

	case len(args) == 2 && args[0] == "x509-verify":
		source, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return "", err
		}
		chain, err := parseChain(raw)
		if err != nil {
			return "", err
		}
		id, _, err := x509svid.Verify(chain, source)
		if err != nil {
			return "", refused{err}
		}
		return id.String(), nil

	case (len(args) == 2 || len(args) == 3) && args[0] == "x509-serve":
		source, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		svid, err := source.GetX509SVID()
		if err != nil {
			return "", err
		}
		listen := "127.0.0.1:0"
		if len(args) == 3 {
			listen = args[2]
		}
		return "", serve(args[1], listen, svid.ID, tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(svid.ID.TrustDomain())))

	case len(args) == 6 && args[0] == "x509-serve-files":
		svid, bundle, td, err := loadFiles(args[2], args[3], args[4], args[5])
		if err != nil {
			return "", err
		}
		return "", serve(args[1], "127.0.0.1:0", svid.ID, tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeMemberOf(td)))

	case len(args) == 3 && args[0] == "x509-dial":
		source, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		td, err := spiffeid.TrustDomainFromString(args[2])
		if err != nil {
			return "", err
		}
		return dial(args[1], tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(td)))

	case len(args) == 6 && args[0] == "x509-dial-files":
		svid, bundle, td, err := loadFiles(args[2], args[3], args[4], args[5])
		if err != nil {
			return "", err
		}
		return dial(args[1], tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeMemberOf(td)))

	case len(args) == 4 && args[0] == "x509-dial-anon":
		td, err := spiffeid.TrustDomainFromString(args[3])
		if err != nil {
			return "", err
		}
		bundle, err := x509bundle.Load(td, args[2])
		if err != nil {
			return "", err
		}
		return dial(args[1], tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeMemberOf(td)))

	case len(args) == 4 && args[0] == "x509-hold":
		source, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return "", err
		}
		defer source.Close()
		td, err := spiffeid.TrustDomainFromString(args[2])
		if err != nil {
			return "", err
		}
		count, err := strconv.Atoi(args[3])
		if err != nil {
			return "", err
		}
		return "", hold(args[1], count, tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(td)))
	}
	return "", fmt.Errorf("bad arguments %q", args)
}

func parseChain(pemBytes []byte) ([]*x509.Certificate, error) {
	bundle, err := x509bundle.Parse(spiffeid.RequireTrustDomainFromString("chain.invalid"), pemBytes)
	if err != nil {
		return nil, err
	}
	return bundle.X509Authorities(), nil
}

// loadFiles reads an SVID and a bundle. The bundle is the one the endpoint
// trusts, whatever trust domain its own SVID is in, so that a test can give an
// endpoint a foreign SVID and see who refuses it.
//
// bundleFile may be followed by ",DOMAIN=FILE" for further trust domains,
// which makes an endpoint that trusts them and authorizes only the first.
func loadFiles(keyFile, chainFile, bundleFile, trustDomain string) (*x509svid.SVID, x509bundle.Source, spiffeid.TrustDomain, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, nil, td, err
	}
	svid, err := x509svid.Load(chainFile, keyFile)
	if err != nil {
		return nil, nil, td, err
	}
	parts := strings.Split(bundleFile, ",")
	bundle, err := x509bundle.Load(td, parts[0])
	if err != nil {
		return nil, nil, td, err
	}
	if len(parts) == 1 {
		return svid, bundle, td, nil
	}
	set := x509bundle.NewSet(bundle)
	for _, more := range parts[1:] {
		name, file, ok := strings.Cut(more, "=")
		if !ok {
			return nil, nil, td, fmt.Errorf("bad bundle %q: want DOMAIN=FILE", more)
		}
		moreTD, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return nil, nil, td, err
		}
		other, err := x509bundle.Load(moreTD, file)
		if err != nil {
			return nil, nil, td, err
		}
		set.Add(other)
	}
	return svid, set, td, nil
}

// peerCA is the key identifier of the CA that signed the peer's certificate.
func peerCA(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return "none"
	}
	return hex.EncodeToString(state.PeerCertificates[0].AuthorityKeyId)
}

func peerID(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return "none"
	}
	id, err := x509svid.IDFromCert(state.PeerCertificates[0])
	if err != nil {
		return "invalid"
	}
	return id.String()
}

func serve(addrFile, listen string, self spiffeid.ID, config *tls.Config) error {
	listener, err := tls.Listen("tcp", listen, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	// Renamed into place, so a reader never sees half an address.
	tmp := addrFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(listener.Addr().String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, addrFile); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				// A refusal is this server's own verdict, not a timeout or the client's alert.
				var netErr net.Error
				var opErr *net.OpError
				switch {
				case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, io.EOF),
					errors.As(err, &opErr) && opErr.Op == "remote error":
					fmt.Fprintln(os.Stderr, "goclient: error:", err)
				default:
					fmt.Fprintln(os.Stderr, "goclient: refused:", err)
				}
				return
			}
			reader := bufio.NewReader(conn)
			for {
				if _, err := reader.ReadString('\n'); err != nil {
					if !errors.Is(err, io.EOF) {
						fmt.Fprintln(os.Stderr, "goclient: read failed:", err)
					}
					return
				}
				state := tlsConn.ConnectionState()
				fmt.Fprintf(conn, "server=%s client=%s client_ca=%s\n", self, peerID(state), peerCA(state))
				// A held connection is alive as long as it is used.
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			}
		}()
	}
}

func dial(addr string, config *tls.Config) (string, error) {
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, config)
	if err := conn.Handshake(); err != nil {
		return "", refused{err}
	}
	if _, err := fmt.Fprintln(conn, "hello"); err != nil {
		return "", refused{err}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", refused{errors.Join(errors.New("no answer after the handshake"), err)}
	}
	state := conn.ConnectionState()
	return fmt.Sprintf("%s server_ca=%s peer=%s", line[:len(line)-1], peerCA(state), peerID(state)), nil
}

// hold keeps one connection and uses it count times, a second apart.
func hold(addr string, count int, config *tls.Config) error {
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn := tls.Client(raw, config)
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	fmt.Printf("%s connected server_ca=%s\n", time.Now().Format(time.RFC3339), peerCA(conn.ConnectionState()))
	for i := 0; i < count; i++ {
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintln(conn, "ping"); err != nil {
			return fmt.Errorf("ping %d: %w", i, err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ping %d: %w", i, err)
		}
		fmt.Printf("%s %s", time.Now().Format(time.RFC3339), line)
		time.Sleep(time.Second)
	}
	return nil
}
