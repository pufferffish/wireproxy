package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/akamensky/argparse"
	"github.com/octeep/wireproxy"
	"suah.dev/protect"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	err := protect.Pledge(promises)
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	// only allow standard stdio operation, file reading, networking, and exec
	pledgeOrPanic("stdio rpath inet dns proc exec")

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		// remove proc and exec if they are not needed
		pledgeOrPanic("stdio rpath inet dns")
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

	if !*daemon {
		// remove proc and exec if they are not needed
		pledgeOrPanic("stdio rpath inet dns")
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

	// no file access is allowed from now on, only networking
	pledgeOrPanic("stdio inet dns")

	tnet, err := wireproxy.StartWireguard(conf.Device)
	if err != nil {
		log.Panic(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tnet)
	}

	select {} // sleep eternally
}
