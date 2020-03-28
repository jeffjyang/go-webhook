package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
)

var COMMAND = "./script.sh"

func webhookAsync(res http.ResponseWriter, _ *http.Request) {
	log.Print("Endpoint: /webhook/async")

	err := exec.Command(COMMAND).Start()

	if err != nil {
		fmt.Fprint(res, "Error triggering script: " + err.Error())
		return
	}
	fmt.Fprint(res, "Triggered command: " + COMMAND)
}

func webhook(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook")

	out, err := exec.Command(COMMAND).Output()

	if err != nil {
		fmt.Fprint(res, "\nAn error occurred:\n" + err.Error())
	}
	if out != nil && len(out) > 0 {
		fmt.Fprint(res, "\nCommand output:\n" + string(out))
	}
}

func main() {
	portPtr := flag.String("port", "8080", "Server port")
	commandPtr := flag.String("command", COMMAND, "Shell command to execute")

	flag.Parse()

	COMMAND = *commandPtr
	log.Print("Starting server on port " + *portPtr)

	http.HandleFunc("/webhook/", webhook)
	http.HandleFunc("/webhook/async/", webhookAsync)

	log.Fatal(http.ListenAndServe(":" + *portPtr, nil))
}
