// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
)

// ErrLineTooLong is returned when reading request or response bodies
// with malformed chunked encoding.
var ErrLineTooLong = http.ErrLineTooLong
