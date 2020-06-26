package main

import (
	"log"

	"github.com/BranLwyd/hrelay/hrelay"
)

func main() {
	srv, err := hrelay.NewServer(&hrelay.ServerConfig{})
	if err != nil {
		log.Fatalf("Couldn't create new hrelay server: %v", err)
	}
	log.Fatalf("Couldn't listen & serve: %v", srv.ListenAndServe(":443"))
}
