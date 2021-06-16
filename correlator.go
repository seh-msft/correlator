// Copyright (c) 2021, Microsoft Corporation, Sean Hinchee
// Licensed under the MIT License.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/seh-msft/burpxml"
	"github.com/seh-msft/cfg"
	"github.com/seh-msft/openapi"
)

// Pair makes a tuple of an api and a path.
type Pair struct {
	api  int
	path int
}

var (
	fuzzy        = flag.Int64("fuzzy", 100, "minimum % match in URL to correlate burp↔openapi paths")
	fromName     = flag.String("from", "", "starting identifier database file name")
	toName       = flag.String("to", "", "substitution identifier database file name")
	burpName     = flag.String("burp", "", "burp input file name")
	b64          = flag.Bool("b64", false, "are burp requests/responses base64-encoded?")
	chatty       = flag.Bool("D", false, "verbose debug output")
	noSub        = flag.Bool("nosub", false, "skip all identifier substitution for replay")
	skipBody     = flag.Bool("pathonly", false, "skip identifier substitutions in the headers/body of a request")
	doReplay     = flag.Bool("replay", false, "replay all correlated requests with new authorization")
	authHeader   = flag.String("auth", "", "'Authorization:' header value for replaying")
	cookieHeader = flag.String("cookie", "", "'Cookie:' header value for replaying (optional with -auth)")
	omitAuth     = flag.Bool("omitauth", false, "omit both 'Authorization:' and 'Cookie:' headers in replay")
	emitJSON     = flag.Bool("json", false, "only emit JSON of correlated requests")
)

// Correlate burp traffic to a openapi JSON file
func main() {
	flag.Parse()
	args := flag.Args()

	/* Argument checks */

	if len(args) < 1 {
		fatal("err: must specify at least one openapi file as an argument")
	}

	if ((*authHeader == "" && *cookieHeader == "") || *omitAuth) && *doReplay {
		fatal("err: if replaying, must specify or explicitly omit auth information (-auth and/or -cookie)")
	}

	var apis []openapi.API

	/* Set up */

	// Non-flagged arguments are api specification files
	for _, name := range args {
		apiFile, err := os.Open(name)
		if err != nil {
			fatal("err: could not open api input file →", err)
		}

		// Load the API
		api, err := openapi.Parse(bufio.NewReader(apiFile))
		if err != nil {
			fatal(fmt.Sprintf(`err: api parse failed for "%s" → %s`, name, err))
		}

		apis = append(apis, api)
	}

	// Output
	var of io.Writer = os.Stdout
	out := bufio.NewWriter(of)
	stderr := bufio.NewWriter(os.Stderr)
	defer stderr.Flush()
	defer out.Flush()

	// Burp input
	if *burpName == "" {
		fatal("err: must specify a burp suite history file (-burp)")
	}

	burpFile, err := os.Open(*burpName)
	if err != nil {
		fatal("err: could not open burp input file →", err)
	}

	history, err := burpxml.Parse(bufio.NewReader(burpFile), *b64)
	if err != nil {
		fatal("err: burp parse failed →", err)
	}

	// Db files
	if len(*fromName) < 1 {
		fatal("err: must specify a 'from' db file (-from)")
	}

	if len(*toName) < 1 {
		fatal("err: must specify a 'to' db file (-to)")
	}

	from := ingestDb(*fromName)
	to := ingestDb(*toName)

	/* Correlate burp → api ⇒ substitute */

	pathCount := uint64(0)

	// Burp index → API indices
	matches := make(map[int][]Pair)

	// Find common paths
	for burpIndex, item := range history.Items {
		// Correct for identifiers in {fooId} form
		item = substitute(left2right, from, item)
		burpPath := item.Path

		for apiIndex, api := range apis {
			// Burp path may be /foo/bar/api/something
			// OpenAPI path may be /api/something
			// So, do contains()
			found, pathIndex := func() (bool, int) {
				if burpIndex < 1 {
					pathCount += uint64(len(api.Paths))
				}

				pathIndex := -1
				for apiPath := range api.Paths {
					pathIndex++

					// Omit "" and "/"
					if len(apiPath) < 2 {
						continue
					}

					if match(out, burpPath, apiPath) {
						if *chatty {
							stderr.WriteString("» matching: " + burpPath + " TO " + apiPath + "\n")
						}
						return true, pathIndex
					}
				}

				return false, -1
			}()

			if !found {
				continue
			}

			// Map of titles, may have multiple matches? - does it matter?
			matches[burpIndex] = append(matches[burpIndex], Pair{apiIndex, pathIndex})
		}
	}

	// Emit matches
	if *chatty {
		for burp, apis := range matches {
			stderr.WriteString(fmt.Sprint("Matched:\n\t", history.Items[burp].Url, "\nIn API's:\n\t", apis, "\n\n"))
		}
	}

	stderr.WriteString(fmt.Sprintln(len(matches), "matches"))
	stderr.WriteString(fmt.Sprintln("Checked", len(history.Items), "items within", pathCount, "api paths"))

	/* Substitute phase */

	// Build the future for replay
	var future []burpxml.Item
	tab := compose(from, to)

	// Convert 'from' items
	for burp := range matches {
		item := history.Items[burp]

		// Transition the identifiers
		if !*noSub {
			item = substitute(left2right, tab, item)
		}

		// Convert auth
		if !*omitAuth {
			// Substitute headers
			if *b64 {
				item.Request.Body = subLine(item.Request.Body, "Authorization:", *authHeader)
				item.Request.Body = subLine(item.Request.Body, "Cookie:", *cookieHeader)
			} else {
				item.Request.Raw = subLine(item.Request.Raw, "Authorization:", *authHeader)
				item.Request.Raw = subLine(item.Request.Raw, "Cookie:", *cookieHeader)
			}
		} else {
			headers := []string{"Authorization:", "Cookie:"}

			// Strip auth entirely
			if *b64 {
				item.Request.Body = stripLines(item.Request.Body, headers)
			} else {
				item.Request.Raw = stripLines(item.Request.Raw, headers)
			}
		}

		future = append(future, item)
	}

	/* Emit phase */

	// Emit JSON of correlated matches
	if enc := json.NewEncoder(out); *emitJSON {
		var out burpxml.Items
		for _, item := range future {
			out.Items = append(out.Items, item)
		}

		err := enc.Encode(out)
		if err != nil {
			fatal("err: could not json encode item -", err)
		}
	}

	/* Replay phase */

	if !*doReplay {
		return
	}

	fatal("replay not yet implemented")
	// TODO - optionall replay and validate requests
	// Consolidate into a module with 'generator'
}

// Substitute line after a given prefix
// Tailored for HTTP headers
func subLine(body, prefix, value string) string {
	lines := strings.Split(body, "\n")

	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			// Assuming all we need is a space
			left := prefix + " "
			right := value

			lines[i] = left + right
		}
	}

	// Remake lines
	out := ""

	for _, line := range lines {
		out += line
		out += "\n"
	}

	return out
}

// Strip lines matching prefix(es)
func stripLines(body string, prefixes []string) string {
	lines := strings.Split(body, "\n")
	var toCut []int

	for i, line := range lines {
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				toCut = append(toCut, i)
			}
		}
	}

	// Cut lines
	for _, i := range toCut {
		lines = append(lines[:i], lines[i+1:]...)
	}

	// Remake lines
	out := ""

	for _, line := range lines {
		out += line
		out += "\n"
	}

	return out
}

// Attempt to match a burp path to a openapi path
func match(out *bufio.Writer, burp, api string) bool {
	// Short-circuit if we know we contain the openapi path
	if strings.HasSuffix(burp, api) {
		return true
	}

	// Fuzzy match
	modified := strings.Replace(burp, api, "", 1)

	// No change? Can't be it
	if len(modified) == len(burp) {
		return false
	}

	origin := float64(len(burp))
	remainder := float64(len(modified))

	// How much of the original string is the openapi path
	delta := int64(100) - int64((remainder/origin)*100)

	if *chatty {
		os.Stderr.WriteString(fmt.Sprintf("delta = %d\n", delta))
	}

	if delta >= *fuzzy {
		return true
	}

	return false
}

// Substitute in `to` identifiers to an item which has been openapi-ified
// ex. /foo/bar/{someId} ⇒ /foo/bar/123-321-abc-def
func right2left(to map[string]string, part string) string {
	// Make the matching ["{foo}"]"abc-123"
	to = flip(to)

	// Iterate all keys
	for id, identifier := range to {
		part = strings.ReplaceAll(part, id, identifier)
	}

	return part
}

// Make a burp item have parity to openapi templates for matching
// ex. /foo/bar/123-321-abc-def ⇒ /foo/bar/{someId}
func left2right(from map[string]string, part string) string {
	// Iterate all keys in case we have foo-123:bar-321 style identifiers
	for identifier, id := range from {
		part = strings.ReplaceAll(part, identifier, id)
	}

	return part
}

// Apply a 'replace' function across a burpxml item
func substitute(replace func(map[string]string, string) string, tab map[string]string, item burpxml.Item) burpxml.Item {
	/* path */
	path := item.Path
	url, err := url.Parse(path)
	if err != nil {
		fatal(`err: could not parse url "`, path, `" →`, err)
	}

	// Will remove argument parameters
	base := url.EscapedPath()

	after := ""

	parts := strings.Split(base, "/")
	for _, part := range parts {
		after += "/"

		part = replace(tab, part)

		// abc-123-321-bde ⇒ {someId}
		after += part
	}

	// Drop a doubled leading '/'
	item.Path = after[1:]

	if *skipBody {
		return item
	}

	/* request headers and body */

	if *b64 {
		// Base64-encoded
		item.Request.Body = replace(tab, item.Request.Body)

	} else {
		// Not base64-encoded
		item.Request.Raw = replace(tab, item.Request.Raw)
	}

	return item
}

// Ingest a db file
// Form of `someId=abc-123-098-def` one per line
func ingestDb(name string) map[string]string {
	file, err := os.Open(name)
	if err != nil {
		fatal(`err: could not open db file "`, name, `" →`, err)
	}

	db, err := cfg.Load(bufio.NewReader(file))
	if err != nil {
		fatal(`err: could not read db file "`, name, `" →`, err)
	}
	db.BuildMap()
	return db.FlatMap()
}

// Compose two maps in the form [{someId}]abc-123
// ex. [a]b, [a]c ⇒ [b]c
func compose(from, to map[string]string) map[string]string {
	out := make(map[string]string)

	for fKey, fVal := range from {
		tVal, ok := to[fKey]
		if !ok {
			continue
		}

		out[fVal] = tVal
	}

	return out
}

// Flip a map's key/value pairs
func flip(in map[string]string) map[string]string {
	out := make(map[string]string)

	for key, value := range in {
		out[value] = key
	}

	return out
}

// Fatal - end program with an error message and newline
func fatal(s ...interface{}) {
	fmt.Fprintln(os.Stderr, s...)
	os.Exit(1)
}
