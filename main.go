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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var OtpSecret []byte

func main() {
	portPtr := flag.String("port", "8080", "Server port")
	secret := flag.String("otp-secret", "",
		"Base32 encoded secret code for OTP authentication. Set this value only if you wish to enable OTP authentication.")

	flag.Parse()

	if *secret != "" {
		var err error
		OtpSecret, err = base32.StdEncoding.DecodeString(*secret)
		if err != nil {
			log.Fatal("Unable to parse OTP secret:\n" + err.Error())
		}
	}
	if OtpSecret == nil {
		log.Print("OTP authentication disabled")
	} else {
		log.Print("OTP authentication enabled")
	}

	log.Print("Starting server on port " + *portPtr)

	http.HandleFunc("/webhook/", webhook)
	http.HandleFunc("/webhook/async/", webhookAsync)
	http.HandleFunc("/webhook/log/", webhookLog)

	log.Fatal(http.ListenAndServe(":" + *portPtr, nil))
}

func webhook(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}
	scriptFile, err := parseScriptFile(req.URL.Path, "/webhook/")
	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
		return
	}

	out, err := exec.Command("/bin/bash", scriptFile).Output()
	go writeLog(scriptFile, out, err)

	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
	}
	if out != nil && len(out) > 0 {
		fmt.Fprint(res, "\n\nScript output:\n\n" + string(out))
	}
}

func webhookAsync(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/async/")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}
	scriptFile, err := parseScriptFile(req.URL.Path, "/webhook/async/")
	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
		return
	}

	go func() {
		out, scriptErr := exec.Command("/bin/bash", scriptFile).Output()
		writeLog(scriptFile, out, scriptErr)
	}()

	fmt.Fprint(res, "Triggered script: " + scriptFile)
}

func webhookLog(res http.ResponseWriter, req *http.Request) {
	log.Print("Endpoint: /webhook/log")
	if !authenticateRequest(req) {
		fmt.Fprint(res, "Unauthorized.")
		return
	}
	scriptFile, err := parseScriptFile(req.URL.Path, "/webhook/log/")
	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
		return
	}

	output, err := readLogFiles(scriptFile)
	if err != nil {
		fmt.Fprint(res, "An error occurred:\n\n" + err.Error())
	}

	fmt.Fprint(res, output)
}

func authenticateRequest(req *http.Request) bool {
	if OtpSecret == nil {
		// otp authentication disabled
		return true
	}
	providedOtp := req.URL.Query().Get("otp")
	expectedOtp := generateOtp()
	return expectedOtp == providedOtp
}

func parseScriptFile(urlPath string, endpoint string) (string, error) {
	scriptFile := strings.TrimPrefix(urlPath, endpoint)
	scriptFile = strings.TrimRight(scriptFile, "/") // remove trailing slashes if any

	if _, err := os.Stat(scriptFile); os.IsNotExist(err) {
		return "", errors.New("error: script file does not exist: " + scriptFile)
	}

	return scriptFile, nil
}

func writeLog(script string, output []byte, err error) {
	errorMsg := ""
	if err != nil {
		errorMsg = "\n\nError messages:\n\n" + err.Error()
	}

	generated :=
		"Script " + script + " last executed at:\n\n" +
		time.Now().Format(time.UnixDate) +
		errorMsg +
		"\n\nOutput:\n\n"
	fullLog := append([]byte(generated), output...)

	_ = ioutil.WriteFile(getLogFileName(script), fullLog, 0666)
}

func readLogFiles(script string) (string, error) {
	logFile := getLogFileName(script)

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return "", errors.New("error: could not find log file (has the script been run?)")
	}

	output, err := ioutil.ReadFile(logFile)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func getLogFileName(scriptFile string) string {
	return strings.TrimSuffix(scriptFile, filepath.Ext(scriptFile)) + ".log"
}

// never roll your own crypto, but for the sake of keeping this project simple this will do.
func generateOtp() string {
	curTime := time.Now().Unix() / 30
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(curTime))

	hmacSha1 := hmac.New(sha1.New, OtpSecret)
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
