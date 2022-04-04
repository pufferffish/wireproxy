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
		log.Fatal(err)
	}
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	err := protect.Unveil(path, flags)
	if err != nil {
		log.Fatal(err)
	}
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

func main() {
	exePath := executablePath()
	unveilOrPanic("/", "r")
	unveilOrPanic(exePath, "x")
	if err := protect.UnveilBlock(); err != nil {
		log.Fatal(err)
	}

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
		log.Fatal(err)
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
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
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
		log.Fatal(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tnet)
	}

	select {} // sleep eternally
}
