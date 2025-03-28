// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP file system request handler

package http

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"time"
)

// A Dir implements [FileSystem] using the native file system restricted to a
// specific directory tree.
//
// While the [FileSystem.Open] method takes '/'-separated paths, a Dir's string
// value is a directory path on the native file system, not a URL, so it is separated
// by [filepath.Separator], which isn't necessarily '/'.
//
// Note that Dir could expose sensitive files and directories. Dir will follow
// symlinks pointing out of the directory tree, which can be especially dangerous
// if serving from a directory in which users are able to create arbitrary symlinks.
// Dir will also allow access to files and directories starting with a period,
// which could expose sensitive directories like .git or sensitive files like
// .htpasswd. To exclude files with a leading period, remove the files/directories
// from the server or create a custom FileSystem implementation.
//
// An empty Dir is treated as ".".
type Dir = http.Dir

// A FileSystem implements access to a collection of named files.
// The elements in a file path are separated by slash ('/', U+002F)
// characters, regardless of host operating system convention.
// See the [FileServer] function to convert a FileSystem to a [Handler].
//
// This interface predates the [fs.FS] interface, which can be used instead:
// the [FS] adapter function converts an fs.FS to a FileSystem.
type FileSystem = http.FileSystem

// A File is returned by a [FileSystem]'s Open method and can be
// served by the [FileServer] implementation.
//
// The methods should behave the same as those on an [*os.File].
type File = http.File

// ServeContent replies to the request using the content in the
// provided ReadSeeker. The main benefit of ServeContent over [io.Copy]
// is that it handles Range requests properly, sets the MIME type, and
// handles If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since,
// and If-Range requests.
//
// If the response's Content-Type header is not set, ServeContent
// first tries to deduce the type from name's file extension and,
// if that fails, falls back to reading the first block of the content
// and passing it to [DetectContentType].
// The name is otherwise unused; in particular it can be empty and is
// never sent in the response.
//
// If modtime is not the zero time or Unix epoch, ServeContent
// includes it in a Last-Modified header in the response. If the
// request includes an If-Modified-Since header, ServeContent uses
// modtime to decide whether the content needs to be sent at all.
//
// The content's Seek method must work: ServeContent uses
// a seek to the end of the content to determine its size.
// Note that [*os.File] implements the [io.ReadSeeker] interface.
//
// If the caller has set w's ETag header formatted per RFC 7232, section 2.3,
// ServeContent uses it to handle requests using If-Match, If-None-Match, or If-Range.
//
// If an error occurs when serving the request (for example, when
// handling an invalid range request), ServeContent responds with an
// error message. By default, ServeContent strips the Cache-Control,
// Content-Encoding, ETag, and Last-Modified headers from error responses.
// The GODEBUG setting httpservecontentkeepheaders=1 causes ServeContent
// to preserve these headers.
func ServeContent(w ResponseWriter, req *Request, name string, modtime time.Time, content io.ReadSeeker) {
	http.ServeContent(w, req, name, modtime, content)
}

// errSeeker is returned by ServeContent's sizeFunc when the content
// doesn't seek properly. The underlying Seeker's error text isn't
// included in the sizeFunc reply so it's not sent over HTTP to end
// users.
var errSeeker = errors.New("seeker can't seek")

// errNoOverlap is returned by serveContent's parseRange if first-byte-pos of
// all of the byte-range-spec values is greater than the content size.
var errNoOverlap = errors.New("invalid range: failed to overlap")

// ServeFile replies to the request with the contents of the named
// file or directory.
//
// If the provided file or directory name is a relative path, it is
// interpreted relative to the current directory and may ascend to
// parent directories. If the provided name is constructed from user
// input, it should be sanitized before calling [ServeFile].
//
// As a precaution, ServeFile will reject requests where r.URL.Path
// contains a ".." path element; this protects against callers who
// might unsafely use [filepath.Join] on r.URL.Path without sanitizing
// it and then use that filepath.Join result as the name argument.
//
// As another special case, ServeFile redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use [ServeContent].
//
// Outside of those two special cases, ServeFile does not use
// r.URL.Path for selecting the file or directory to serve; only the
// file or directory provided in the name argument is used.
func ServeFile(w ResponseWriter, r *Request, name string) {
	http.ServeFile(w, r, name)
}

// ServeFileFS replies to the request with the contents
// of the named file or directory from the file system fsys.
// The files provided by fsys must implement [io.Seeker].
//
// If the provided name is constructed from user input, it should be
// sanitized before calling [ServeFileFS].
//
// As a precaution, ServeFileFS will reject requests where r.URL.Path
// contains a ".." path element; this protects against callers who
// might unsafely use [filepath.Join] on r.URL.Path without sanitizing
// it and then use that filepath.Join result as the name argument.
//
// As another special case, ServeFileFS redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use [ServeContent].
//
// Outside of those two special cases, ServeFileFS does not use
// r.URL.Path for selecting the file or directory to serve; only the
// file or directory provided in the name argument is used.
func ServeFileFS(w ResponseWriter, r *Request, fsys fs.FS, name string) {
	http.ServeFileFS(w, r, fsys, name)
}

// FS converts fsys to a [FileSystem] implementation,
// for use with [FileServer] and [NewFileTransport].
// The files provided by fsys must implement [io.Seeker].
func FS(fsys fs.FS) FileSystem {
	return http.FS(fsys)
}

// FileServer returns a handler that serves HTTP requests
// with the contents of the file system rooted at root.
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
//
// To use the operating system's file system implementation,
// use [http.Dir]:
//
//	http.Handle("/", http.FileServer(http.Dir("/tmp")))
//
// To use an [fs.FS] implementation, use [http.FileServerFS] instead.
func FileServer(root FileSystem) Handler {
	return http.FileServer(root)
}

// FileServerFS returns a handler that serves HTTP requests
// with the contents of the file system fsys.
// The files provided by fsys must implement [io.Seeker].
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
//
//	http.Handle("/", http.FileServerFS(fsys))
func FileServerFS(root fs.FS) Handler {
	return FileServer(FS(root))
}
