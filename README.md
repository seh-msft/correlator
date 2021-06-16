# correlator

Correlate Burp Suite XML history files to one or more OpenAPI JSON specification files. 

Burp Suite XML history files can be processed and prepared with the [bx tool](https://github.com/seh-msft/bx) which uses the [burpxml module](https://github.com/seh-msft/burpxml). 

Written in [Go](https://golang.org). 

## Build

	go build

## Database format

The db text file format is in the form:

```
# A comment
someId=abc-123
anotherId=321-def
fooBar=asdf-321-123-asdf
```

Parsing is done via the [cfg module](https://github.com/seh-msft/cfg). 

## Usage

```
Usage of correlator:
  -D    verbose debug output
  -auth string
        'Authorization:' header value for replaying
  -b64
        are burp requests/responses base64-encoded?
  -burp string
        burp input file name
  -cookie string
        'Cookie:' header value for replaying (optional with -auth)
  -from string
        starting identifier database file name
  -fuzzy int
        minimum % match in URL to correlate burp↔openapi paths (default 100)
  -json
        only emit JSON of correlated requests
  -nosub
        skip all identifier substitution for replay
  -omitauth
        omit both 'Authorization:' and 'Cookie:' headers in replay
  -pathonly
        skip identifier substitutions in the headers/body of a request
  -replay
        replay all correlated requests with new authorization
  -to string
        substitution identifier database file name
```

## Scripts

Supporting scripts are in [./scripts](./scripts) and were implemented for use under WSL.

Some supporting scripts are written in the [rc](https://github.com/rakitzis/rc) shell. 

Rc can be installed on Debian-like systems with `sudo apt-get install rc`. 

* getbearer → the **attacker** user must be logged in the the Azure CLI ;; return an access token for the **attacker**
* testnewuser → replays the correlator Burp corpus with a new user's token and checks for non-4xx HTTP responses
* testnoauth → replays the correlator Burp corpus with all authorization stripped

Note that none of the scripts are mandatory for this tool to work, they simply demonstrate automation of the openapi tooling in this repository. 

Some scripts rely on [sendhttp](https://github.com/seh-msft/sendhttp) and [jsonfs](https://github.com/droyo/jsonfs) being in their `PATH`. 

## Examples

Mount correlated requests as a file system:

```
$ go run correlator.go -fuzzy 12 -json -burp history.xml -from alice.db -to bob.db jsons/*  > corr.json
$ jsonfs corr.json &
$ 9pfs -p 5640 127.0.0.1 ~/n/json
$ cd ~/n/json
$ ls */*/Request
Items/0/Request:
Base64  Body  Raw

Items/1/Request:
Base64  Body  Raw

Items/2/Request:
Base64  Body  Raw

Items/3/Request:
Base64  Body  Raw

Items/4/Request:
Base64  Body  Raw
$ 
```

Get the paths correlated, strip Authorization/Cookie headers, and don't substitute identifiers:

```
correlator$ go run correlator.go -fuzzy 12 -json -omitauth -nosub -burp history.xml -from alice.db -to bob.db specifications/* | jq '.Items[].Path'
3 matches
Checked 955 items within 377225 api paths
"/someapi/transaction/123-abc-456-def/first"
"/someapi/invoices/5678/second"
"/someapi/accounts/1234/third"
correlator$
```
