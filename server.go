package hrelay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	pb "github.com/BranLwyd/hrelay/proto/hrelay_go_proto"
)

// TODO: shutdown
// TODO: add acme support (need to support GetCertificate, specifying additional NextProtos)
// TODO: need to ignore "already closed" error on close attempts? (as in rspd) [if so, repeatedly call errors.Unwrap until we get a syscall.Errno, then check if the errno is ENOTCONN?]

type Server struct {
	cfg    *tls.Config
	logger *log.Logger

	mu      sync.Mutex // protects waiters
	waiters []*waitingConn
}

type ServerConfig struct {
	// Certificate corresponds to tls.Config's Certificates.
	Certificate tls.Certificate

	// ClientCAs corresponds to tls.Config's ClientCAs.
	ClientCAs *x509.CertPool

	// If set, the server will log information about its operations to this logger.
	Logger *log.Logger
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	// Set up TLS configuration.
	tlsCFG := &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			// Determine the client-requested protocol to use.
			negotiatedProtocol := ""
			for _, proto := range hi.SupportedProtos {
				if proto == "hrelay" {
					negotiatedProtocol = proto
				}
			}
			if negotiatedProtocol == "" {
				// Per RFC 7301, this should be a "no_application_protocol" alert, but Go's TLS library does not allow sending alerts.
				// Returning an error from GetConfigForClient always causes an "internal error".
				return nil, fmt.Errorf("protocol negoatiation failure")
			}

			return &tls.Config{
				Certificates: []tls.Certificate{cfg.Certificate},
				MinVersion:   tls.VersionTLS13,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    cfg.ClientCAs,
				NextProtos:   []string{negotiatedProtocol},
			}, nil
		},
	}

	return &Server{cfg: tlsCFG, logger: cfg.Logger}, nil
}

func (s *Server) ListenAndServe(addr string) error {
	lst, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("couldn't listen: %w", err)
	}
	return s.Serve(lst)
}

func (s *Server) Serve(lst net.Listener) error {
	defer lst.Close()
	for {
		conn, err := lst.Accept()
		if err != nil {
			return fmt.Errorf("couldn't accept: %w", err)
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(c net.Conn) {
	conn := tls.Server(c, s.cfg)
	s.clog(conn, "New connection")
	defer func() {
		if err := conn.Close(); err != nil {
			s.clog(conn, "Error while closing connection: %v", err)
		} else {
			s.clog(conn, "Connection closed")
		}
	}()

	// Retrieve the underlying syscall.RawConn, if possible. This is required for connection liveness checking.
	var rawConn syscall.RawConn
	if sc, ok := c.(syscall.Conn); ok {
		rc, err := sc.SyscallConn()
		if err != nil {
			s.clog(conn, "Couldn't get raw connection: %v", err)
		}
		rawConn = rc
	} else {
		s.clog(conn, "Can't make syscalls on this connection; liveness checking is disabled")
	}

	// Perform TLS handshake and determine principal.
	// Until the connection is authenticated via the handshake, we set a read/write deadline to mitigate DoS attempts.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.clog(conn, "Couldn't set handshake deadline: %v", err)
		return
	}
	if err := conn.Handshake(); err != nil {
		s.clog(conn, "Handshake error: %v", err)
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.clog(conn, "Couldn't unset handshake deadline: %v", err)
		return
	}
	principal, err := principal(conn.ConnectionState().VerifiedChains)
	if err != nil {
		s.clog(conn, "Couldn't determine principal: %v", err)
		return
	}
	s.clog(conn, "Principal is %q", principal)

	// Read request message, and pair up with another connection.
	req := &pb.ConnectRequest{}
	if err := readMessage(conn, req); err != nil {
		s.clog(conn, "Couldn't read connection request: %v", err)
		return
	}

	otherPrincipal, otherConn, closeWG, totalMatches, err := s.findPairedConnection(principal, conn, rawConn, req)
	if err != nil {
		s.clog(conn, "Couldn't pair with another connection: %v", err)
		return
	}
	defer closeWG.Wait()
	defer closeWG.Done()
	s.clog(conn, "Paired with %s [%q]", otherConn.RemoteAddr(), otherPrincipal)

	// Write response.
	if err := writeMessage(conn, &pb.ConnectResponse{
		ConnectedPrincipal:   otherPrincipal,
		RemainingConnections: int64(totalMatches - 1),
	}); err != nil {
		s.clog(conn, "Couldn't write connection response: %v", err)
		return
	}

	// Copy data from our connection to the other connection, until it closes.
	if _, err := io.Copy(otherConn, conn); err != nil {
		s.clog(conn, "Couldn't copy to other connection: %v", err)
		return
	}
	if err := otherConn.CloseWrite(); err != nil {
		s.clog(conn, "Couldn't write-close other connection: %v", err)
		return
	}
}

func (s *Server) findPairedConnection(principal string, conn *tls.Conn, rawConn syscall.RawConn, req *pb.ConnectRequest) (otherPrincipal string, _ *tls.Conn, closeWG *sync.WaitGroup, totalMatches int, _ error) {
	// Prepare our waitingConn.
	connectPrincipals := map[string]struct{}{}
	for _, p := range req.ConnectPrincipals {
		connectPrincipals[p] = struct{}{}
	}
	waitCh := make(chan waiterMsg)
	wc := &waitingConn{
		principal:         principal,
		connectAny:        req.ConnectAny,
		connectPrincipals: connectPrincipals,
		conn:              conn,
		rawConn:           rawConn,
		ch:                waitCh,
	}

	removeWaiter := func(i int, err error) *waitingConn {
		wc := s.waiters[i]
		if err != nil {
			wc.ch <- waiterMsg{"", nil, nil, err}
		}
		s.waiters[i], s.waiters = s.waiters[len(s.waiters)-1], s.waiters[:len(s.waiters)-1]
		return wc
	}

	// Try to find a matching connection among waiting connections.
	// Also garbage collect any clients that got bored of waiting and closed the connection, while we're at it.
	s.mu.Lock()
	i, matchIdx := 0, -1
	for i < len(s.waiters) {
		if s.waiters[i].rawConn != nil {
			isOpen, err := isConnOpen(s.waiters[i].rawConn)
			if err != nil {
				removeWaiter(i, fmt.Errorf("couldn't check connection liveness: %w", err))
				continue
			}
			if !isOpen {
				removeWaiter(i, errors.New("client closed connection"))
				continue
			}
		}

		if wc.matches(s.waiters[i]) {
			totalMatches++
			matchIdx = i
		}
		i++
	}
	if matchIdx != -1 {
		// We found a match! Pair our connection up with the matching waiter.
		otherWC := removeWaiter(matchIdx, nil)
		s.mu.Unlock()

		wg := &sync.WaitGroup{}
		wg.Add(2)
		otherWC.ch <- waiterMsg{principal, conn, wg, nil}
		return otherWC.principal, otherWC.conn, wg, totalMatches, nil
	}

	// No current waiters match, which means we need to wait. Add us to the
	// waitlist, then wait for a paired connection on our channel.
	s.waiters = append(s.waiters, wc)
	s.mu.Unlock()

	wm := <-waitCh
	return wm.principal, wm.conn, wm.wg, 1, wm.err
}

type waitingConn struct {
	principal         string
	connectAny        bool
	connectPrincipals map[string]struct{}

	conn    *tls.Conn
	rawConn syscall.RawConn // May be nil, if conn not backed by a syscall.RawConn. This disables connection-liveness testing.
	ch      chan<- waiterMsg
}

func (wc *waitingConn) matches(otherWC *waitingConn) bool {
	// Make sure these connections don't describe the same peer.
	if wc.principal == otherWC.principal {
		return false
	}

	// Check if wc wants to connect with otherWC.
	if !wc.connectAny {
		if _, ok := wc.connectPrincipals[otherWC.principal]; !ok {
			return false
		}
	}

	// Check if otherWC wants to connect with wc.
	if !otherWC.connectAny {
		if _, ok := otherWC.connectPrincipals[wc.principal]; !ok {
			return false
		}
	}

	return true
}

type waiterMsg struct {
	principal string
	conn      *tls.Conn
	wg        *sync.WaitGroup
	err       error
}

func (s *Server) log(format string, v ...interface{}) {
	if s.logger == nil {
		return
	}
	s.logger.Printf(format, v...)
}

func (s *Server) clog(conn net.Conn, format string, v ...interface{}) {
	if s.logger == nil {
		return
	}
	newV := make([]interface{}, 1+len(v))
	newV[0] = conn.RemoteAddr()
	copy(newV[1:], v)
	s.logger.Printf("[%s] "+format, newV...)
}
