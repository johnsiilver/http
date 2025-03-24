// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP server. See RFC 7230 through 7235.

package http

import (
	"errors"
	"net"
	"net/http"
	"time"
	_ "unsafe" // for linkname
)

// Errors used by the HTTP server.
var (
	// ErrBodyNotAllowed is returned by ResponseWriter.Write calls
	// when the HTTP method or response code does not permit a
	// body.
	ErrBodyNotAllowed = errors.New("http: request method or response status code does not allow body")

	// ErrHijacked is returned by ResponseWriter.Write calls when
	// the underlying connection has been hijacked using the
	// Hijacker interface. A zero-byte write on a hijacked
	// connection will return ErrHijacked without any other side
	// effects.
	ErrHijacked = errors.New("http: connection has been hijacked")

	// ErrContentLength is returned by ResponseWriter.Write calls
	// when a Handler set a Content-Length response header with a
	// declared size and then attempted to write more bytes than
	// declared.
	ErrContentLength = errors.New("http: wrote more than the declared Content-Length")

	// Deprecated: ErrWriteAfterFlush is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrWriteAfterFlush = errors.New("unused")
)

// A Handler responds to an HTTP request.
//
// [Handler.ServeHTTP] should write reply headers and data to the [ResponseWriter]
// and then return. Returning signals that the request is finished; it
// is not valid to use the [ResponseWriter] or read from the
// [Request.Body] after or concurrently with the completion of the
// ServeHTTP call.
//
// Depending on the HTTP client software, HTTP protocol version, and
// any intermediaries between the client and the Go server, it may not
// be possible to read from the [Request.Body] after writing to the
// [ResponseWriter]. Cautious handlers should read the [Request.Body]
// first, and then reply.
//
// Except for reading the body, handlers should not modify the
// provided Request.
//
// If ServeHTTP panics, the server (the caller of ServeHTTP) assumes
// that the effect of the panic was isolated to the active request.
// It recovers the panic, logs a stack trace to the server error log,
// and either closes the network connection or sends an HTTP/2
// RST_STREAM, depending on the HTTP protocol. To abort a handler so
// the client sees an interrupted response but the server doesn't log
// an error, panic with the value [ErrAbortHandler].
type Handler = http.Handler

// A ResponseWriter interface is used by an HTTP handler to
// construct an HTTP response.
//
// A ResponseWriter may not be used after [Handler.ServeHTTP] has returned.
type ResponseWriter = http.ResponseWriter

// The Flusher interface is implemented by ResponseWriters that allow
// an HTTP handler to flush buffered data to the client.
//
// The default HTTP/1.x and HTTP/2 [ResponseWriter] implementations
// support [Flusher], but ResponseWriter wrappers may not. Handlers
// should always test for this ability at runtime.
//
// Note that even for ResponseWriters that support Flush,
// if the client is connected through an HTTP proxy,
// the buffered data may not reach the client until the response
// completes.
type Flusher = http.Flusher

// The Hijacker interface is implemented by ResponseWriters that allow
// an HTTP handler to take over the connection.
//
// The default [ResponseWriter] for HTTP/1.x connections supports
// Hijacker, but HTTP/2 connections intentionally do not.
// ResponseWriter wrappers may also not support Hijacker. Handlers
// should always test for this ability at runtime.
type Hijacker = http.Hijacker

// The CloseNotifier interface is implemented by ResponseWriters which
// allow detecting when the underlying connection has gone away.
//
// This mechanism can be used to cancel long operations on the server
// if the client has disconnected before the response is ready.
//
// Deprecated: the CloseNotifier interface predates Go's context package.
// New code should use [Request.Context] instead.
type CloseNotifier = http.CloseNotifier

var (
	// ServerContextKey is a context key. It can be used in HTTP
	// handlers with Context.Value to access the server that
	// started the handler. The associated value will be of
	// type *Server.
	ServerContextKey = http.ServerContextKey

	// LocalAddrContextKey is a context key. It can be used in
	// HTTP handlers with Context.Value to access the local
	// address the connection arrived on.
	// The associated value will be of type net.Addr.
	LocalAddrContextKey = http.LocalAddrContextKey
)

// This should be >= 512 bytes for DetectContentType,
// but otherwise it's somewhat arbitrary.
const bufferBeforeChunkingSize = 2048

// TrailerPrefix is a magic prefix for [ResponseWriter.Header] map keys
// that, if present, signals that the map entry is actually for
// the response trailers, and not the response headers. The prefix
// is stripped after the ServeHTTP call finishes and the values are
// sent in the trailers.
//
// This mechanism is intended only for trailers that are not known
// prior to the headers being written. If the set of trailers is fixed
// or known before the header is written, the normal Go trailers mechanism
// is preferred:
//
//	https://pkg.go.dev/net/http#ResponseWriter
//	https://pkg.go.dev/net/http#example-ResponseWriter-Trailers
const TrailerPrefix = "Trailer:"

// DefaultMaxHeaderBytes is the maximum permitted size of the headers
// in an HTTP request.
// This can be overridden by setting [Server.MaxHeaderBytes].
const DefaultMaxHeaderBytes = 1 << 20 // 1 MB

// TimeFormat is the time format to use when generating times in HTTP
// headers. It is like [time.RFC1123] but hard-codes GMT as the time
// zone. The time being formatted must be in UTC for Format to
// generate the correct format.
//
// For parsing this time format, see [ParseTime].
const TimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// maxPostHandlerReadBytes is the max number of Request.Body bytes not
// consumed by a handler that the server will read from the client
// in order to keep a connection alive. If there are more bytes
// than this, the server, to be paranoid, instead sends a
// "Connection close" response.
//
// This number is approximately what a typical machine's TCP buffer
// size is anyway.  (if we have the bytes on the machine, we might as
// well read them)
const maxPostHandlerReadBytes = 256 << 10

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// [Handler] that calls f.
type HandlerFunc = http.HandlerFunc

// Helper handlers

// Error replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The error message should be plain text.
//
// Error deletes the Content-Length header,
// sets Content-Type to “text/plain; charset=utf-8”,
// and sets X-Content-Type-Options to “nosniff”.
// This configures the header properly for the error message,
// in case the caller had set it up expecting a successful output.
func Error(w ResponseWriter, error string, code int) {
	http.Error(w, error, code)
}

// NotFound replies to the request with an HTTP 404 not found error.
func NotFound(w ResponseWriter, r *Request) { Error(w, "404 page not found", StatusNotFound) }

// NotFoundHandler returns a simple request handler
// that replies to each request with a “404 page not found” reply.
func NotFoundHandler() Handler { return HandlerFunc(NotFound) }

// StripPrefix returns a handler that serves HTTP requests by removing the
// given prefix from the request URL's Path (and RawPath if set) and invoking
// the handler h. StripPrefix handles a request for a path that doesn't begin
// with prefix by replying with an HTTP 404 not found error. The prefix must
// match exactly: if the prefix in the request contains escaped characters
// the reply is also an HTTP 404 not found error.
func StripPrefix(prefix string, h Handler) Handler {
	return http.StripPrefix(prefix, h)
}

// Redirect replies to the request with a redirect to url,
// which may be a path relative to the request path.
//
// The provided code should be in the 3xx range and is usually
// [StatusMovedPermanently], [StatusFound] or [StatusSeeOther].
//
// If the Content-Type header has not been set, [Redirect] sets it
// to "text/html; charset=utf-8" and writes a small HTML body.
// Setting the Content-Type header to any value, including nil,
// disables that behavior.
func Redirect(w ResponseWriter, r *Request, url string, code int) {
	http.Redirect(w, r, url, code)
}

// RedirectHandler returns a request handler that redirects
// each request it receives to the given url using the given
// status code.
//
// The provided code should be in the 3xx range and is usually
// [StatusMovedPermanently], [StatusFound] or [StatusSeeOther].
func RedirectHandler(url string, code int) Handler {
	return http.RedirectHandler(url, code)
}

// ServeMux is an HTTP request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that
// most closely matches the URL.
//
// # Patterns
//
// Patterns can match the method, host and path of a request.
// Some examples:
//
//   - "/index.html" matches the path "/index.html" for any host and method.
//   - "GET /static/" matches a GET request whose path begins with "/static/".
//   - "example.com/" matches any request to the host "example.com".
//   - "example.com/{$}" matches requests with host "example.com" and path "/".
//   - "/b/{bucket}/o/{objectname...}" matches paths whose first segment is "b"
//     and whose third segment is "o". The name "bucket" denotes the second
//     segment and "objectname" denotes the remainder of the path.
//
// In general, a pattern looks like
//
//	[METHOD ][HOST]/[PATH]
//
// All three parts are optional; "/" is a valid pattern.
// If METHOD is present, it must be followed by at least one space or tab.
//
// Literal (that is, non-wildcard) parts of a pattern match
// the corresponding parts of a request case-sensitively.
//
// A pattern with no method matches every method. A pattern
// with the method GET matches both GET and HEAD requests.
// Otherwise, the method must match exactly.
//
// A pattern with no host matches every host.
// A pattern with a host matches URLs on that host only.
//
// A path can include wildcard segments of the form {NAME} or {NAME...}.
// For example, "/b/{bucket}/o/{objectname...}".
// The wildcard name must be a valid Go identifier.
// Wildcards must be full path segments: they must be preceded by a slash and followed by
// either a slash or the end of the string.
// For example, "/b_{bucket}" is not a valid pattern.
//
// Normally a wildcard matches only a single path segment,
// ending at the next literal slash (not %2F) in the request URL.
// But if the "..." is present, then the wildcard matches the remainder of the URL path, including slashes.
// (Therefore it is invalid for a "..." wildcard to appear anywhere but at the end of a pattern.)
// The match for a wildcard can be obtained by calling [Request.PathValue] with the wildcard's name.
// A trailing slash in a path acts as an anonymous "..." wildcard.
//
// The special wildcard {$} matches only the end of the URL.
// For example, the pattern "/{$}" matches only the path "/",
// whereas the pattern "/" matches every path.
//
// For matching, both pattern paths and incoming request paths are unescaped segment by segment.
// So, for example, the path "/a%2Fb/100%25" is treated as having two segments, "a/b" and "100%".
// The pattern "/a%2fb/" matches it, but the pattern "/a/b/" does not.
//
// # Precedence
//
// If two or more patterns match a request, then the most specific pattern takes precedence.
// A pattern P1 is more specific than P2 if P1 matches a strict subset of P2’s requests;
// that is, if P2 matches all the requests of P1 and more.
// If neither is more specific, then the patterns conflict.
// There is one exception to this rule, for backwards compatibility:
// if two patterns would otherwise conflict and one has a host while the other does not,
// then the pattern with the host takes precedence.
// If a pattern passed to [ServeMux.Handle] or [ServeMux.HandleFunc] conflicts with
// another pattern that is already registered, those functions panic.
//
// As an example of the general rule, "/images/thumbnails/" is more specific than "/images/",
// so both can be registered.
// The former matches paths beginning with "/images/thumbnails/"
// and the latter will match any other path in the "/images/" subtree.
//
// As another example, consider the patterns "GET /" and "/index.html":
// both match a GET request for "/index.html", but the former pattern
// matches all other GET and HEAD requests, while the latter matches any
// request for "/index.html" that uses a different method.
// The patterns conflict.
//
// # Trailing-slash redirection
//
// Consider a [ServeMux] with a handler for a subtree, registered using a trailing slash or "..." wildcard.
// If the ServeMux receives a request for the subtree root without a trailing slash,
// it redirects the request by adding the trailing slash.
// This behavior can be overridden with a separate registration for the path without
// the trailing slash or "..." wildcard. For example, registering "/images/" causes ServeMux
// to redirect a request for "/images" to "/images/", unless "/images" has
// been registered separately.
//
// # Request sanitizing
//
// ServeMux also takes care of sanitizing the URL request path and the Host
// header, stripping the port number and redirecting any request containing . or
// .. segments or repeated slashes to an equivalent, cleaner URL.
// Escaped path elements such as "%2e" for "." and "%2f" for "/" are preserved
// and aren't considered separators for request routing.
//
// # Compatibility
//
// The pattern syntax and matching behavior of ServeMux changed significantly
// in Go 1.22. To restore the old behavior, set the GODEBUG environment variable
// to "httpmuxgo121=1". This setting is read once, at program startup; changes
// during execution will be ignored.
//
// The backwards-incompatible changes include:
//   - Wildcards are just ordinary literal path segments in 1.21.
//     For example, the pattern "/{x}" will match only that path in 1.21,
//     but will match any one-segment path in 1.22.
//   - In 1.21, no pattern was rejected, unless it was empty or conflicted with an existing pattern.
//     In 1.22, syntactically invalid patterns will cause [ServeMux.Handle] and [ServeMux.HandleFunc] to panic.
//     For example, in 1.21, the patterns "/{"  and "/a{x}" match themselves,
//     but in 1.22 they are invalid and will cause a panic when registered.
//   - In 1.22, each segment of a pattern is unescaped; this was not done in 1.21.
//     For example, in 1.22 the pattern "/%61" matches the path "/a" ("%61" being the URL escape sequence for "a"),
//     but in 1.21 it would match only the path "/%2561" (where "%25" is the escape for the percent sign).
//   - When matching patterns to paths, in 1.22 each segment of the path is unescaped; in 1.21, the entire path is unescaped.
//     This change mostly affects how paths with %2F escapes adjacent to slashes are treated.
//     See https://go.dev/issue/21955 for details.
type ServeMux = http.ServeMux

// NewServeMux allocates and returns a new [ServeMux].
func NewServeMux() *ServeMux {
	return &ServeMux{}
}

// DefaultServeMux is the default [ServeMux] used by [Serve].
var DefaultServeMux = http.DefaultServeMux

// Handle registers the handler for the given pattern in [DefaultServeMux].
// The documentation for [ServeMux] explains how patterns are matched.
func Handle(pattern string, handler Handler) {
	http.Handle(pattern, handler)
}

// HandleFunc registers the handler function for the given pattern in [DefaultServeMux].
// The documentation for [ServeMux] explains how patterns are matched.
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	http.HandleFunc(pattern, handler)
}

// Serve accepts incoming HTTP connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// HTTP/2 support is only enabled if the Listener returns [*tls.Conn]
// connections and they were configured with "h2" in the TLS
// Config.NextProtos.
//
// Serve always returns a non-nil error.
func Serve(l net.Listener, handler Handler) error {
	return http.Serve(l, handler)
}

// ServeTLS accepts incoming HTTPS connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// Additionally, files containing a certificate and matching private key
// for the server must be provided. If the certificate is signed by a
// certificate authority, the certFile should be the concatenation
// of the server's certificate, any intermediates, and the CA's certificate.
//
// ServeTLS always returns a non-nil error.
func ServeTLS(l net.Listener, handler Handler, certFile, keyFile string) error {
	return http.ServeTLS(l, handler, certFile, keyFile)
}

// A Server defines parameters for running an HTTP server.
// The zero value for Server is a valid configuration.
type Server = http.Server

// shutdownPollIntervalMax is the max polling interval when checking
// quiescence during Server.Shutdown. Polling starts with a small
// interval and backs off to the max.
// Ideally we could find a solution that doesn't involve polling,
// but which also doesn't have a high runtime cost (and doesn't
// involve any contentious mutexes), but that is left as an
// exercise for the reader.
const shutdownPollIntervalMax = 500 * time.Millisecond

// A ConnState represents the state of a client connection to a server.
// It's used by the optional [Server.ConnState] hook.
type ConnState = http.ConnState

const (
	// StateNew represents a new connection that is expected to
	// send a request immediately. Connections begin at this
	// state and then transition to either StateActive or
	// StateClosed.
	StateNew ConnState = iota

	// StateActive represents a connection that has read 1 or more
	// bytes of a request. The Server.ConnState hook for
	// StateActive fires before the request has entered a handler
	// and doesn't fire again until the request has been
	// handled. After the request is handled, the state
	// transitions to StateClosed, StateHijacked, or StateIdle.
	// For HTTP/2, StateActive fires on the transition from zero
	// to one active request, and only transitions away once all
	// active requests are complete. That means that ConnState
	// cannot be used to do per-request work; ConnState only notes
	// the overall state of the connection.
	StateActive

	// StateIdle represents a connection that has finished
	// handling a request and is in the keep-alive state, waiting
	// for a new request. Connections transition from StateIdle
	// to either StateActive or StateClosed.
	StateIdle

	// StateHijacked represents a hijacked connection.
	// This is a terminal state. It does not transition to StateClosed.
	StateHijacked

	// StateClosed represents a closed connection.
	// This is a terminal state. Hijacked connections do not
	// transition to StateClosed.
	StateClosed
)

// AllowQuerySemicolons returns a handler that serves requests by converting any
// unescaped semicolons in the URL query to ampersands, and invoking the handler h.
//
// This restores the pre-Go 1.17 behavior of splitting query parameters on both
// semicolons and ampersands. (See golang.org/issue/25192). Note that this
// behavior doesn't match that of many proxies, and the mismatch can lead to
// security issues.
//
// AllowQuerySemicolons should be invoked before [Request.ParseForm] is called.
func AllowQuerySemicolons(h Handler) Handler {
	return http.AllowQuerySemicolons(h)
}

var testHookServerServe func(*Server, net.Listener) // used if non-nil

// ErrServerClosed is returned by the [Server.Serve], [ServeTLS], [ListenAndServe],
// and [ListenAndServeTLS] methods after a call to [Server.Shutdown] or [Server.Close].
var ErrServerClosed = errors.New("http: Server closed")

// ListenAndServe listens on the TCP network address addr and then calls
// [Serve] with handler to handle requests on incoming connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string, handler Handler) error {
	return http.ListenAndServe(addr, handler)
}

// ListenAndServeTLS acts identically to [ListenAndServe], except that it
// expects HTTPS connections. Additionally, files containing a certificate and
// matching private key for the server must be provided. If the certificate
// is signed by a certificate authority, the certFile should be the concatenation
// of the server's certificate, any intermediates, and the CA's certificate.
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error {
	return http.ListenAndServeTLS(addr, certFile, keyFile, handler)
}

// TimeoutHandler returns a [Handler] that runs h with the given time limit.
//
// The new Handler calls h.ServeHTTP to handle each request, but if a
// call runs for longer than its time limit, the handler responds with
// a 503 Service Unavailable error and the given message in its body.
// (If msg is empty, a suitable default message will be sent.)
// After such a timeout, writes by h to its [ResponseWriter] will return
// [ErrHandlerTimeout].
//
// TimeoutHandler supports the [Pusher] interface but does not support
// the [Hijacker] or [Flusher] interfaces.
func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler {
	return http.TimeoutHandler(h, dt, msg)
}

// ErrHandlerTimeout is returned on [ResponseWriter] Write calls
// in handlers which have timed out.
var ErrHandlerTimeout = errors.New("http: Handler timeout")

// MaxBytesHandler returns a [Handler] that runs h with its [ResponseWriter] and [Request.Body] wrapped by a MaxBytesReader.
func MaxBytesHandler(h Handler, n int64) Handler {
	return http.MaxBytesHandler(h, n)
}
