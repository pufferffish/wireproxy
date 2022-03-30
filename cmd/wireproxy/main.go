package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/akamensky/argparse"
	"github.com/octeep/wireproxy"
)

const daemonProcess = "daemon-process"

func main() {
	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}

	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")

	config := parser.String("c", "config", &argparse.Options{Required: true, Help: "Path of configuration file"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	conf, err := wireproxy.ParseConfig(*config)
	if err != nil {
		log.Panic(err)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		programPath, err := os.Executable()
		if err != nil {
			programPath = args[0]
		}

		newArgs := []string{daemonProcess}
		newArgs = append(newArgs, args[1:]...)
		cmd := exec.Command(programPath, newArgs...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
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
