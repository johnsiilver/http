// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP Response reading and parsing.

package http

import (
	"bufio"
	"errors"
	"net/http"

	"golang.org/x/net/http/httpguts"
)

var respExcludeHeader = map[string]bool{
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// Response represents the response from an HTTP request.
//
// The [Client] and [Transport] return Responses from servers once
// the response headers have been received. The response body
// is streamed on demand as the Body field is read.
type Response = http.Response

// ErrNoLocation is returned by the [Response.Location] method
// when no Location header is present.
var ErrNoLocation = errors.New("http: no Location header in response")

// ReadResponse reads and returns an HTTP response from r.
// The req parameter optionally specifies the [Request] that corresponds
// to this [Response]. If nil, a GET request is assumed.
// Clients must call resp.Body.Close when finished reading resp.Body.
// After that call, clients can inspect resp.Trailer to find key/value
// pairs included in the response trailer.
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error) {
	return http.ReadResponse(r, req)
}

// RFC 7234, section 5.4: Should treat
//
//	Pragma: no-cache
//
// like
//
//	Cache-Control: no-cache
func fixPragmaCacheControl(header Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}

// isProtocolSwitchResponse reports whether the response code and
// response header indicate a successful protocol upgrade response.
func isProtocolSwitchResponse(code int, h Header) bool {
	return code == StatusSwitchingProtocols && isProtocolSwitchHeader(h)
}

// isProtocolSwitchHeader reports whether the request or response header
// is for a protocol switch.
func isProtocolSwitchHeader(h Header) bool {
	return h.Get("Upgrade") != "" &&
		httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade")
}
