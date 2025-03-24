// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP Request reading and parsing.

package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	_ "unsafe" // for linkname

	"github.com/johnsiilver/http/internal/ascii"

	"golang.org/x/net/idna"
)

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

// ErrMissingFile is returned by FormFile when the provided file field name
// is either not present in the request or not a file field.
var ErrMissingFile = errors.New("http: no such file")

// ProtocolError represents an HTTP protocol error.
//
// Deprecated: Not all errors in the http package related to protocol errors
// are of type ProtocolError.
type ProtocolError struct {
	ErrorString string
}

func (pe *ProtocolError) Error() string { return pe.ErrorString }

// Is lets http.ErrNotSupported match errors.ErrUnsupported.
func (pe *ProtocolError) Is(err error) bool {
	return pe == ErrNotSupported && err == errors.ErrUnsupported
}

var (
	// ErrNotSupported indicates that a feature is not supported.
	//
	// It is returned by ResponseController methods to indicate that
	// the handler does not support the method, and by the Push method
	// of Pusher implementations to indicate that HTTP/2 Push support
	// is not available.
	ErrNotSupported = &ProtocolError{"feature not supported"}

	// Deprecated: ErrUnexpectedTrailer is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrUnexpectedTrailer = &ProtocolError{"trailer header without chunked transfer encoding"}

	// ErrMissingBoundary is returned by Request.MultipartReader when the
	// request's Content-Type does not include a "boundary" parameter.
	ErrMissingBoundary = &ProtocolError{"no multipart boundary param in Content-Type"}

	// ErrNotMultipart is returned by Request.MultipartReader when the
	// request's Content-Type is not multipart/form-data.
	ErrNotMultipart = &ProtocolError{"request Content-Type isn't multipart/form-data"}

	// Deprecated: ErrHeaderTooLong is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrHeaderTooLong = &ProtocolError{"header too long"}

	// Deprecated: ErrShortBody is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrShortBody = &ProtocolError{"entity body too short"}

	// Deprecated: ErrMissingContentLength is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrMissingContentLength = &ProtocolError{"missing ContentLength in HEAD response"}
)

func badStringError(what, val string) error { return fmt.Errorf("%s %q", what, val) }

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Host":              true, // not in Header map anyway
	"User-Agent":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for [Request.Write] and [RoundTripper].
type Request = http.Request


// ErrNoCookie is returned by Request's Cookie method when a cookie is not found.
var ErrNoCookie = errors.New("http: named cookie not present")

// multipartByReader is a sentinel value.
// Its presence in Request.MultipartForm indicates that parsing of the request
// body has been handed off to a MultipartReader instead of ParseMultipartForm.
var multipartByReader = &multipart.Form{
	Value: make(map[string][]string),
	File:  make(map[string][]*multipart.FileHeader),
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// NOTE: This is not intended to reflect the actual Go version being used.
// It was changed at the time of Go 1.1 release because the former User-Agent
// had ended up blocked by some intrusion detection systems.
// See https://codereview.appspot.com/7532043.
const defaultUserAgent = "Go-http-client/1.1"

// errMissingHost is returned by Write when there is no Host or URL present in
// the Request.
var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")

// requestBodyReadError wraps an error from (*Request).write to indicate
// that the error came from a Read call on the Request.Body.
// This error type should not escape the net/http package to users.
type requestBodyReadError struct{ error }

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if ascii.Is(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

// ParseHTTPVersion parses an HTTP version string according to RFC 7230, section 2.6.
// "HTTP/1.0" returns (1, 0, true). Note that strings without
// a minor version, such as "HTTP/2", are not valid.
func ParseHTTPVersion(vers string) (major, minor int, ok bool) {
	switch vers {
	case "HTTP/1.1":
		return 1, 1, true
	case "HTTP/1.0":
		return 1, 0, true
	}
	if !strings.HasPrefix(vers, "HTTP/") {
		return 0, 0, false
	}
	if len(vers) != len("HTTP/X.Y") {
		return 0, 0, false
	}
	if vers[6] != '.' {
		return 0, 0, false
	}
	maj, err := strconv.ParseUint(vers[5:6], 10, 0)
	if err != nil {
		return 0, 0, false
	}
	min, err := strconv.ParseUint(vers[7:8], 10, 0)
	if err != nil {
		return 0, 0, false
	}
	return int(maj), int(min), true
}

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// NewRequest wraps [NewRequestWithContext] using [context.Background].
func NewRequest(method, url string, body io.Reader) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, url, body)
}

// NewRequestWithContext returns a new [Request] given a method, URL, and
// optional body.
//
// If the provided body is also an [io.Closer], the returned
// [Request.Body] is set to body and will be closed (possibly
// asynchronously) by the Client methods Do, Post, and PostForm,
// and [Transport.RoundTrip].
//
// NewRequestWithContext returns a Request suitable for use with
// [Client.Do] or [Transport.RoundTrip]. To create a request for use with
// testing a Server Handler, either use the [net/http/httptest.NewRequest] function,
// use [ReadRequest], or manually update the Request fields.
// For an outgoing client request, the context
// controls the entire lifetime of a request and its response:
// obtaining a connection, sending the request, and reading the
// response headers and body. See the Request type's documentation for
// the difference between inbound and outbound request fields.
//
// If body is of type [*bytes.Buffer], [*bytes.Reader], or
// [*strings.Reader], the returned request's ContentLength is set to its
// exact value (instead of -1), GetBody is populated (so 307 and 308
// redirects can replay the body), and Body is set to [NoBody] if the
// ContentLength is 0.
func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
	return http.NewRequestWithContext(ctx, method, url, body)
}


// ReadRequest reads and parses an incoming request from b.
//
// ReadRequest is a low-level function and should only be used for
// specialized applications; most code should use the [Server] to read
// requests and handle them via the [Handler] interface. ReadRequest
// only supports HTTP/1.x requests. For HTTP/2, use golang.org/x/net/http2.
func ReadRequest(b *bufio.Reader) (*Request, error) {
	return http.ReadRequest(b)
}

// MaxBytesReader is similar to [io.LimitReader] but is intended for
// limiting the size of incoming request bodies. In contrast to
// io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a
// non-nil error of type [*MaxBytesError] for a Read beyond the limit,
// and closes the underlying reader when its Close method is called.
//
// MaxBytesReader prevents clients from accidentally or maliciously
// sending a large request and wasting server resources. If possible,
// it tells the [ResponseWriter] to close the connection after the limit
// has been reached.
func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	return http.MaxBytesReader(w, r, n)
}

// MaxBytesError is returned by [MaxBytesReader] when its read limit is exceeded.
type MaxBytesError = http.MaxBytesError
