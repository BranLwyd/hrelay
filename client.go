package hrelay

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	pb "github.com/BranLwyd/hrelay/proto/hrelay_go_proto"
)

type Conn struct{ conn *tls.Conn }

var _ net.Conn = &Conn{}

// net.Conn methods.
func (c *Conn) Read(b []byte) (n int, err error)   { return c.conn.Read(b) }
func (c *Conn) Write(b []byte) (n int, err error)  { return c.conn.Write(b) }
func (c *Conn) Close() error                       { return c.conn.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *Conn) CloseWrite() error { return c.conn.CloseWrite() }

type ClientConfig struct {
	// A list of peers that we want to connect to.
	ConnectPeerNames []string

	// If true, we will connect to any peer that wishes to connect to us.
	ConnectAny bool

	// IdentityCertificate is the client-authentication certificate proving this client's identity.
	IdentityCertificate tls.Certificate

	// ServerCAs are the CAs used to verify the server's certificate. If nil, the host's root CA set is used.
	ServerCAs *x509.CertPool

	// PeerCAs are the CAs used to verify peer certificates.
	PeerCAs *x509.CertPool
}

func Dial(network, addr string, cfg *ClientConfig) (_ *Conn, peer string, remainingConns int64, _ error) {
	// Determine server name from address.
	cpos := strings.LastIndex(addr, ":")
	if cpos == -1 {
		cpos = len(addr)
	}
	serverName := addr[:cpos]

	// Dial the server & connect to it.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, "", 0, fmt.Errorf("couldn't dial: %w", err)
	}
	return Connect(conn, serverName, cfg)
}

func Connect(c net.Conn, serverName string, cfg *ClientConfig) (_ *Conn, peer string, remainingConns int64, retErr error) {
	defer func() {
		if retErr != nil {
			c.Close()
		}
	}()

	// Determine our own name from our identity certificate.
	name, err := principal([][]*x509.Certificate{{cfg.IdentityCertificate.Leaf}})
	if err != nil {
		return nil, "", 0, fmt.Errorf("couldn't determine client name from identity certificate: %w", err)
	}

	// Perform TLS handshake with server.
	conn := tls.Client(c, &tls.Config{
		Certificates: []tls.Certificate{cfg.IdentityCertificate},
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      cfg.ServerCAs,
		NextProtos:   []string{"hrelay"},
	})
	if err := conn.Handshake(); err != nil {
		return nil, "", 0, fmt.Errorf("handshake failure with server: %w", err)
	}
	if cs := conn.ConnectionState(); !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != "hrelay" {
		return nil, "", 0, fmt.Errorf("protocol negotiation failure")
	}

	// Send request, read response. This might be waiting for a while if no peer is available.
	if err := writeMessage(conn, &pb.ConnectRequest{
		ConnectPrincipals: cfg.ConnectPeerNames,
		ConnectAny:        cfg.ConnectAny,
	}); err != nil {
		return nil, "", 0, fmt.Errorf("couldn't write connection request: %w", err)
	}
	var resp pb.ConnectResponse
	if err := readMessage(conn, &resp); err != nil {
		return nil, "", 0, fmt.Errorf("couldn't read connection response: %w", err)
	}

	// Make sure the peer the server connected us to is one that we want.
	if !cfg.ConnectAny {
		peerIsRequested := false
		for _, p := range cfg.ConnectPeerNames {
			if p == name {
				// Don't accept connections to ourselves, even if specified.
				// (This would break peer-to-peer client/server determination below.)
				continue
			}
			if resp.ConnectedPrincipal == p {
				peerIsRequested = true
				break
			}
		}
		if !peerIsRequested {
			return nil, "", 0, fmt.Errorf("connected to unrequested peer")
		}
	}

	// Perform peer-to-peer TLS handshake to verify peer.
	if isServer := name < resp.ConnectedPrincipal; isServer {
		conn = tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cfg.IdentityCertificate},
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    cfg.PeerCAs,

			VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
				p, err := principal(verifiedChains)
				if err != nil {
					return fmt.Errorf("couldn't determine peer name from certificates: %w", err)
				}
				if p != resp.ConnectedPrincipal {
					return fmt.Errorf("peer name mismatch (expected %q, got %q)", resp.ConnectedPrincipal, p)
				}
				return nil
			},
		})
	} else {
		conn = tls.Client(conn, &tls.Config{
			Certificates: []tls.Certificate{cfg.IdentityCertificate},
			MinVersion:   tls.VersionTLS13,
			ServerName:   resp.ConnectedPrincipal,
			RootCAs:      cfg.PeerCAs,
		})
	}
	if err := conn.Handshake(); err != nil {
		return nil, "", 0, fmt.Errorf("handshake failure with peer: %w", err)
	}

	return &Conn{conn}, resp.ConnectedPrincipal, resp.RemainingConnections, nil
}
