package main

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/BranLwyd/hrelay/hrelay"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	pb "github.com/BranLwyd/hrelay/proto/hrelayd_go_proto"
)

var (
	configFile = flag.String("config", "", "The hrelayd configuration file to use.")
)

func main() {
	// Parse & validate flags.
	flag.Parse()
	if *configFile == "" {
		log.Fatalf("Missing required --config flag")
	}

	// Parse and validate config.
	cfgBytes, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Couldn't read config file: %v", err)
	}
	cfg := &pb.Config{}
	if err := proto.UnmarshalText(string(cfgBytes), cfg); err != nil {
		log.Fatalf("Couldn't parse config file: %v", err)
	}
	if cfg.HostName == "" {
		log.Fatalf("Config is missing host_name")
	}
	if cfg.CertDir == "" {
		log.Fatalf("Config is missing cert_dir")
	}
	if cfg.ClientCaCerts == "" {
		log.Fatalf("Config is missing client_ca_certs")
	}

	// Parse client CA certs.
	caBytes, err := ioutil.ReadFile(cfg.ClientCaCerts)
	if err != nil {
		log.Fatalf("Couldn't read client CA certs: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("Couldn't parse any certificates for client CAs")
	}

	// Begin serving.
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.HostName),
		Cache:      autocert.DirCache(cfg.CertDir),
		Email:      cfg.Email,
	}
	srv := hrelay.NewServer(&hrelay.ServerConfig{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{acme.ALPNProto},
		ClientCAs:      clientCAs,
		Logger:         log.New(os.Stderr, "", log.LstdFlags),
	})
	if err != nil {
		log.Fatalf("Couldn't create new hrelay server: %v", err)
	}
	log.Fatalf("Couldn't listen & serve: %v", srv.ListenAndServe(":443"))
}
