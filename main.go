package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

var SCRIPT string
var OTP_SECRET []byte

var OUTPUT_LOG_FILE = "output.log"

func main() {
	portPtr := flag.String("port", "8080", "Server port")
	scriptPtr := flag.String("script", "script.sh", "Shell script to execute")
	secret := flag.String("otp-secret", "",
		"Base32 encoded secret code if you wish to enable OTP authentication. Set this value if you wish to enable OTP authentication.")

	flag.Parse()

	// check file permissions on the shell script
	script := *scriptPtr
	info, err := os.Stat(script)
	if err != nil {
		log.Fatal("An error occurred:\n" + err.Error())
	}
	mode := info.Mode()
	if mode&0100 == 0 {
		log.Fatal("Script " + script + " is not executable. Double check its file permissions.")
	}

	SCRIPT = "./" + script

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

	if _, err := os.Stat(OUTPUT_LOG_FILE); os.IsNotExist(err) {
		_, fileErr := os.Create(OUTPUT_LOG_FILE)
		if fileErr != nil {
			log.Fatal("Unable to create log file:\n" + fileErr.Error())
		}
	}

	log.Print("Starting server on port " + *portPtr)

	http.HandleFunc("/webhook/", webhook)
	http.HandleFunc("/webhook/async/", webhookAsync)
	http.HandleFunc("/webhook/log/", webhookLog)

	log.Fatal(http.ListenAndServe(":" + *portPtr, nil))
}


func webhook(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}

	out, err := exec.Command(SCRIPT).Output()
	go writeLog(out)

	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
	}
	if out != nil && len(out) > 0 {
		fmt.Fprint(res, "Script output:\n\n" + string(out))
	}
}

func webhookAsync(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/async")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}

	go func() {
		out, _ := exec.Command(SCRIPT).Output()
		writeLog(out)
	}()

	fmt.Fprint(res, "Triggered script: " + SCRIPT)
}

func webhookLog(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/log")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}

	output, err := readLogFiles()
	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
	}

	fmt.Fprint(res, output)
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

func writeLog(log []byte) {
	generated :=
		"Script " + SCRIPT + " last executed at:\n\n" +
		time.Now().Format(time.UnixDate) +
		"\n\nOutput:\n\n";
	fullLog := append([]byte(generated), log...)
	_ = ioutil.WriteFile(OUTPUT_LOG_FILE, fullLog, 0666)
}

func readLogFiles() (string, error) {
	// check if log file exists
	if _, err := os.Stat(OUTPUT_LOG_FILE); os.IsNotExist(err) {
		return "", errors.New("error: unable to find log file(s)")
	}

	output, err := ioutil.ReadFile(OUTPUT_LOG_FILE)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// never roll your own crypto, but for the sake of keeping this project simple this will do.
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
