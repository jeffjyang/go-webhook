package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"time"
)

var COMMAND = "./script.sh"
var OTP_SECRET []byte

func main() {
	portPtr := flag.String("port", "8080", "Server port")
	commandPtr := flag.String("command", COMMAND, "Shell command to execute")
	secret := flag.String("otp-secret", "", "Base32 encoded secret code if you wish to enable OTP authentication")

	flag.Parse()

	COMMAND = *commandPtr

	if *secret != "" {
		var err error
		OTP_SECRET, err = base32.StdEncoding.DecodeString(*secret)
		if err != nil {
			log.Fatal("Unable to parse OTP secret:\n" + err.Error())
		}
	}

	if OTP_SECRET == nil {
		log.Print("OTP authentication disabled")
	} else {
		log.Print("OTP authentication enabled")
	}
	log.Print("Starting server on port " + *portPtr)

	http.HandleFunc("/webhook/", webhook)
	http.HandleFunc("/webhook/async/", webhookAsync)

	log.Fatal(http.ListenAndServe(":" + *portPtr, nil))
}


func webhook(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}

	out, err := exec.Command(COMMAND).Output()

	if err != nil {
		fmt.Fprint(res, "\nAn error occurred:\n" + err.Error())
	}
	if out != nil && len(out) > 0 {
		fmt.Fprint(res, "\nCommand output:\n" + string(out))
	}
}

func webhookAsync(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/async")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}

	err := exec.Command(COMMAND).Start()

	if err != nil {
		fmt.Fprint(res, "Error triggering script: " + err.Error())
		return
	}
	fmt.Fprint(res, "Triggered command: " + COMMAND)
}

func authenticateRequest(req *http.Request) bool {
	if OTP_SECRET == nil {
		// otp authentication disabled
		return true
	}
	return verifyOtp(req.URL.Query().Get("otp"))
}

func verifyOtp(otp string) bool {
	expected := generateOtp()
	return otp == expected
}

// never roll your own crypto, but for the sake of keeping this project simple, this will do.
func generateOtp() string {
	curTime := time.Now().Unix() / 30
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(curTime))

	hmacSha1 := hmac.New(sha1.New, OTP_SECRET)
	hmacSha1.Write(message)
	hash := hmacSha1.Sum(nil)

	offset := hash[len(hash) - 1] & 0b1111
	truncatedHash := hash[offset : offset + 4]

	code := binary.BigEndian.Uint32(truncatedHash)
	code = (code & 0x7fffffff) % 1000000

	otp := strconv.FormatInt(int64(code), 10)
	for len(otp) < 6 {
		otp = "0" + otp
	}
	return otp
}
