package hrelay

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	pb "github.com/BranLwyd/hrelay/proto/hrelay_go_proto"
)

type Client struct {
	name       string
	serverAddr string
	idCert     tls.Certificate
	serverCAs  *x509.CertPool
	peerCAs    *x509.CertPool
}

type ClientConfig struct {
	// ServerAddress is the address of the hrelay server to connect to.
	ServerAddress string

	// IdentityCertificate is the client-authentication certificate proving this client's identity.
	IdentityCertificate tls.Certificate

	// ServerCAs are the CAs used to verify the server's certificate. If nil, the host's root CA set is used.
	ServerCAs *x509.CertPool

	// PeerCAs are the CAs used to verify peer certificates.
	PeerCAs *x509.CertPool
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	name, err := principal([][]*x509.Certificate{{cfg.IdentityCertificate.Leaf}})
	if err != nil {
		return nil, fmt.Errorf("couldn't determine client name from identity certificate: %w", err)
	}

	return &Client{
		name:       name,
		serverAddr: cfg.ServerAddress,
		idCert:     cfg.IdentityCertificate,
		serverCAs:  cfg.ServerCAs,
		peerCAs:    cfg.PeerCAs,
	}, nil
}

func (c *Client) Connect(principals ...string) (_ net.Conn, peer string, remainingConns int64, _ error) {
	return c.connect(&pb.ConnectRequest{ConnectPrincipals: principals})
}

func (c *Client) ConnectAny() (_ net.Conn, peer string, remainingConns int64, _ error) {
	return c.connect(&pb.ConnectRequest{ConnectAny: true})
}

func (c *Client) connect(req *pb.ConnectRequest) (_ net.Conn, peer string, remainingConns int64, retErr error) {
	// Dial & handshake with server.
	conn, err := tls.Dial("tcp", c.serverAddr, &tls.Config{
		Certificates: []tls.Certificate{c.idCert},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      c.serverCAs,
		NextProtos:   []string{"hrelay"},
	})
	if err != nil {
		return nil, "", 0, fmt.Errorf("couldn't dial server: %w", err)
	}
	defer func() {
		if retErr != nil {
			conn.Close()
		}
	}()
	if cs := conn.ConnectionState(); !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != "hrelay" {
		return nil, "", 0, fmt.Errorf("protocol negotiation failure (protocol = %q, mutual = %v)", cs.NegotiatedProtocol, cs.NegotiatedProtocolIsMutual)
	}

	// Send request, read response. This might be waiting for a while if no peer is available.
	if err := writeMessage(conn, req); err != nil {
		return nil, "", 0, fmt.Errorf("couldn't write connection request: %w", err)
	}
	var resp pb.ConnectResponse
	if err := readMessage(conn, &resp); err != nil {
		return nil, "", 0, fmt.Errorf("couldn't read connection response: %w", err)
	}

	// TODO: check if resp.ConnectedPrincipal is one that we asked for (lol)

	// Perform peer-to-peer handshake to verify peer.
	if isServer := c.name < resp.ConnectedPrincipal; isServer {
		conn = tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{c.idCert},
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    c.peerCAs,

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
			Certificates: []tls.Certificate{c.idCert},
			MinVersion:   tls.VersionTLS13,
			ServerName:   resp.ConnectedPrincipal,
			RootCAs:      c.peerCAs,
		})
	}
	if err := conn.Handshake(); err != nil {
		return nil, "", 0, fmt.Errorf("couldn't handshake with peer: %w", err)
	}

	return conn, resp.ConnectedPrincipal, resp.RemainingConnections, nil
}
