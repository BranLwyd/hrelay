package hrelay

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/golang/protobuf/proto"
)

func readMessage(r io.Reader, msg proto.Message) error {
	var szBytes [4]byte
	if _, err := io.ReadFull(r, szBytes[:]); err != nil {
		return fmt.Errorf("couldn't read size: %w", err)
	}
	sz := binary.BigEndian.Uint32(szBytes[:])
	buf := make([]byte, sz)
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("couldn't read message: %w", err)
	}
	if err := proto.Unmarshal(buf, msg); err != nil {
		return fmt.Errorf("couldn't unmarshal message: %w", err)
	}
	return nil
}

func writeMessage(w io.Writer, msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("couldn't marshal message: %w", err)
	}
	var szBytes [4]byte
	binary.BigEndian.PutUint32(szBytes[:], uint32(len(buf)))
	if _, err := w.Write(szBytes[:]); err != nil {
		return fmt.Errorf("couldn't write size: %w", err)
	}
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("couldn't write message: %w", err)
	}
	return nil
}

func principal(verifiedChains [][]*x509.Certificate) (string, error) {
	var principal string
	for _, chain := range verifiedChains {
		for _, name := range chain[0].DNSNames {
			switch {
			case name == "":
				continue
			case principal == "":
				principal = name
			case principal != name:
				return "", fmt.Errorf("multiple principals in supplied client certificates (%q & %q)", principal, name)
			}
		}
	}
	if principal == "" {
		return "", errors.New("no principal in supplied client certificates")
	}
	return principal, nil
}

func isConnOpen(conn syscall.RawConn) (bool, error) {
	isOpen := true
	var sysErr error
	if err := conn.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, _, err := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case n == 0 && err == nil:
			isOpen = false
		case err != syscall.EAGAIN && err != syscall.EWOULDBLOCK:
			sysErr = err
		}
		return true
	}); err != nil {
		return false, fmt.Errorf("couldn't read raw connection: %w", err)
	}
	return isOpen, sysErr
}

func isAlreadyClosed(err error) bool {
	for err != nil {
		// TODO: replace this gross hack if/when it becomes possible to do so
		if err.Error() == "use of closed network connection" || err.Error() == "tls: use of closed connection" {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
