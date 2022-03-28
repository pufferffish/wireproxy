package main

import (
	"fmt"
	"log"
	"os"

	"github.com/octeep/wireproxy"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: wireproxy [config file path]")
		return
	}

	conf, err := wireproxy.ParseConfig(os.Args[1])
	if err != nil {
		log.Panic(err)
	}

	tnet, err := wireproxy.StartWireguard(conf.Device)
	if err != nil {
		log.Panic(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tnet)
	}

	select {} // sleep eternally
}
