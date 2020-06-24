package hrelay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestSimpleConnection(t *testing.T) {
	// Generate certificates.
	caC, err := caCert()
	if err != nil {
		t.Fatalf("Couldn't generate CA certificate: %v", err)
	}

	srvC, err := serverCert(caC, "localhost")
	if err != nil {
		t.Fatalf("Couldn't generate server certificate: %v", err)
	}

	pcaC, err := caCert()
	if err != nil {
		t.Fatalf("Couldn't generate principal CA certificate: %v", err)
	}

	aliceC, err := principalCert(pcaC, "alice")
	if err != nil {
		t.Fatalf("Couldn't generate Alice's certificate: %v", err)
	}

	bobC, err := principalCert(pcaC, "bob")
	if err != nil {
		t.Fatalf("Couldn't generate Bob's certificate: %v", err)
	}

	caCP := x509.NewCertPool()
	caCP.AddCert(caC.cert)

	peerCP := x509.NewCertPool()
	peerCP.AddCert(pcaC.cert)

	// Create server & clients.
	go func() {
		srv, err := NewServer(&ServerConfig{
			Certificate: srvC.tlsCertificate(),
			ClientCAs:   peerCP,
		})
		if err != nil {
			t.Fatalf("Couldn't create server: %v", err)
		}
		if err := srv.ListenAndServe(); err != nil {
			t.Errorf("Server couldn't listen & serve: %v", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		alice, err := NewClient(&ClientConfig{
			ServerAddress:       "localhost:10443",
			IdentityCertificate: aliceC.tlsCertificate(),
			ServerCAs:           caCP,
			PeerCAs:             peerCP,
		})
		if err != nil {
			t.Errorf("Couldn't create Alice client: %v", err)
			return
		}
		conn, peer, remainingConns, err := alice.Connect("bob")
		if err != nil {
			t.Errorf("Couldn't connect to Bob: %v", err)
			return
		}
		defer conn.Close()
		log.Printf("Alice: %v [mutual: %v]", conn.(*tls.Conn).ConnectionState().NegotiatedProtocol, conn.(*tls.Conn).ConnectionState().NegotiatedProtocolIsMutual) // XXX
		if peer != "bob" {
			t.Errorf("Unexpected peer: want %q, got %q", "bob", peer)
		}
		if remainingConns != 0 {
			t.Errorf("Unexpected remaining-connections count: want %d, got %d", 0, remainingConns)
		}
		if _, err := conn.Write([]byte("Hello from Alice!")); err != nil {
			t.Errorf("Couldn't write to Bob: %v", err)
		}
		if err := conn.(*tls.Conn).CloseWrite(); err != nil {
			t.Errorf("Couldn't close-write connection to Bob: %v", err)
		}
		readBytes, err := ioutil.ReadAll(conn)
		if err != nil {
			t.Errorf("Couldn't read from connection to Bob: %v", err)
		} else if read := string(readBytes); read != "Hello from Bob!" {
			t.Errorf("Unexpected message from Bob: want %q, got %q", "Hello from Bob!", read)
		}
	}()

	go func() {
		defer wg.Done()
		bob, err := NewClient(&ClientConfig{
			ServerAddress:       "localhost:10443",
			IdentityCertificate: bobC.tlsCertificate(),
			ServerCAs:           caCP,
			PeerCAs:             peerCP,
		})
		if err != nil {
			t.Errorf("Couldn't create Bob client: %v", err)
			return
		}
		conn, peer, remainingConns, err := bob.Connect("alice")
		if err != nil {
			t.Errorf("Couldn't connect to Alice: %v", err)
			return
		}
		defer conn.Close()
		log.Printf("Bob: %v [mutual: %v]", conn.(*tls.Conn).ConnectionState().NegotiatedProtocol, conn.(*tls.Conn).ConnectionState().NegotiatedProtocolIsMutual) // XXX
		if peer != "alice" {
			t.Errorf("Unexpected peer: want %q, got %q", "alice", peer)
		}
		if remainingConns != 0 {
			t.Errorf("Unexpected remaining-connections count: want %d, got %d", 0, remainingConns)
		}
		if _, err := conn.Write([]byte("Hello from Bob!")); err != nil {
			t.Errorf("Couldn't write to Alice: %v", err)
		}
		if err := conn.(*tls.Conn).CloseWrite(); err != nil {
			t.Errorf("Couldn't close-write connection to Alice: %v", err)
		}
		readBytes, err := ioutil.ReadAll(conn)
		if err != nil {
			t.Errorf("Couldn't read from connection to Alice: %v", err)
		} else if read := string(readBytes); read != "Hello from Alice!" {
			t.Errorf("Unexpected message from Alice: want %q, got %q", "Hello from Alice!", read)
		}
	}()

	wg.Wait()
}

type certKey struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func (ck certKey) tlsCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{ck.cert.Raw},
		PrivateKey:  ck.key,
		Leaf:        ck.cert,
	}
}

func (ck certKey) isZero() bool { return ck.cert == nil && ck.key == nil }

func caCert() (certKey, error) {
	return generateCert(certKey{}, x509.Certificate{
		KeyUsage: x509.KeyUsageCertSign,
		IsCA:     true,
	})
}

func serverCert(signer certKey, serverName string) (certKey, error) {
	return generateCert(signer, x509.Certificate{
		Subject: pkix.Name{
			CommonName: serverName,
		},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

func principalCert(signer certKey, principalName string) (certKey, error) {
	return generateCert(signer, x509.Certificate{
		Subject: pkix.Name{
			CommonName: principalName,
		},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	})
}

func generateCert(signer certKey, template x509.Certificate) (certKey, error) {
	// Generate keys/template values.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return certKey{}, fmt.Errorf("couldn't generate key: %w", err)
	}
	sn, err := serialNumber()
	if err != nil {
		return certKey{}, fmt.Errorf("couldn't generate serial number: %w", err)
	}

	// Fill in common fields in provided template.
	template.SerialNumber = sn
	template.NotBefore = time.Now().Add(-time.Minute)
	template.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	template.BasicConstraintsValid = true

	// If the zero value is given for signer, create a self-signed certificate.
	if signer.isZero() {
		signer = certKey{&template, privKey}
	}

	// Generate certificate bytes & re-parse (lol) back into an *x509.Certificate.
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, signer.cert, pubKey, signer.key)
	if err != nil {
		return certKey{}, fmt.Errorf("couldn't generate certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certKey{}, fmt.Errorf("couldn't parse certificate: %w", err)
	}
	return certKey{cert, privKey}, nil

}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func serialNumber() (*big.Int, error) { return rand.Int(rand.Reader, serialNumberLimit) }
