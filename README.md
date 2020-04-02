# go-webhook

A simple webhook server with just enough security to keep honest people honest. Trigger shell scripts via http calls!

## Basic Usage

To run the server: 
```
./go-webhook -h
Usage of ./go-webhook:
  -otp-secret string
    	Base32 encoded secret code if you wish to enable OTP authentication. Set this value if you wish to enable OTP authentication.
  -port string
    	Server port (default "8080")
  -script string
    	Shell script to execute (default "script.sh")
``` 

``` 
# Examples: 
$ ./go-webhook 
$ ./go-webhook -script=deploy.sh -port=5000 -otp-secret=4S62BZNFXXSZLCRO
``` 

--------

### Endpoints: 

Interacting with the server can be done through your browser's address bar, simply by going to the appropriate endpoint: 

**Run the shell script and wait for its completion:**
```
$ curl http://localhost:8080/webhook/
Script output:

Hello bash!
```

**Run the shell script but don't wait for completion:** 
```
$ curl http://localhost:8080/webhook/async/
Triggered script: ./script.sh    
```

**Get the timestamp and output of the last script execution:** 
```
$ curl http://localhost:8080/webhook/log/
Script ./script.sh last executed at:

Thu Apr  2 10:15:10 PDT 2020

Output:

Hello bash!
```

--------

### OTP authentication:

If OTP authentication is enabled, simply append `?otp=<your OTP code>` to the end of the url to authenticate. 
OTP authentication will be required for every endpoint. 

**Authenticating write a valid OTP:**
```
$ curl http://localhost:8080/webhook/?otp=123456
Script output:

Hello bash!
```

**If an invalid OTP is provided:** 
```
$ curl http://localhost:8080/webhook/?otp=123456
Unauthorized. 
```
