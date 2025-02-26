package fetch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

// NewRequest returns a new RequestConfig given a method, URL, optional body, optional headers.
// Body type: slice, map, struct, string, []byte, io.Reader, fmt.Stringer
func NewRequest(method, u string, body any, headers map[string]string) (*http.Request, error) {
	var reqBody io.Reader = http.NoBody
	if body != nil {
		// Convert body to io.Reader
		switch data := body.(type) {
		default:
			kind := reflect.ValueOf(body).Kind()
			if kind != reflect.Struct && kind != reflect.Map && kind != reflect.Array && kind != reflect.Slice {
				break
			}

			j, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			if headers == nil {
				headers = make(map[string]string)
			}
			if _, ok := headers["Content-Type"]; !ok {
				headers["Content-Type"] = "application/json"
			}
			reqBody = bytes.NewReader(j)
		case io.Reader:
			reqBody = data
		case fmt.Stringer:
			reqBody = bytes.NewBufferString(data.String())
		case string:
			reqBody = bytes.NewBufferString(data)
		case []byte:
			reqBody = bytes.NewBuffer(data)
		}
	}

	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		return nil, err
	}

	// set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// ReadRequest returns a new RequestConfig given a http text with argument.
// /foo
// GET /foo
// GET /foo HTTP/1.1
func ReadRequest(request string) (req *http.Request, err error) {
	tp := newTextprotoReader(bufio.NewReader(strings.NewReader(request)))
	defer putTextprotoReader(tp)

	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}

	req = &http.Request{Body: http.NoBody}
	var rawURI string

	req.Method, rawURI, req.Proto = parseRequestLine(s)
	if !validMethod(req.Method) {
		return nil, fmt.Errorf("invalid method %s", req.Method)
	}
	var ok bool
	if req.ProtoMajor, req.ProtoMinor, ok = http.ParseHTTPVersion(req.Proto); !ok {
		return nil, fmt.Errorf("malformed HTTP version %s", req.Proto)
	}

	if req.URL, err = url.ParseRequestURI(rawURI); err != nil {
		return nil, err
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	req.Header = http.Header(mimeHeader)
	if len(req.Header["Host"]) > 1 {
		return nil, fmt.Errorf("too many Host headers")
	}

	// RFC 7230, section 5.3: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host

	fixPragmaCacheControl(req.Header)

	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	if req.Method != http.MethodHead && tp.R.Buffered() > 0 {
		// Read body and fix content-length
		body := new(bytes.Buffer)
		if _, err = tp.R.WriteTo(body); err != nil {
			return nil, err
		}
		if body.Len() == 0 {
			req.Body = http.NoBody
		} else {
			req.ContentLength = int64(body.Len())
			req.Body = io.NopCloser(body)
		}
	}

	return req, nil
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
// Default proto HTTP/1.1.
func parseRequestLine(line string) (method, requestURI, proto string) {
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 {
		// default GET request
		return http.MethodGet, line, "HTTP/1.1"
	}
	if !ok2 {
		return method, requestURI, "HTTP/1.1"
	}
	return method, requestURI, proto
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
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

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers.
func shouldClose(major, minor int, header http.Header, removeCloseHeader bool) bool {
	if major < 1 {
		return true
	}

	conv := header["Connection"]
	hasClose := httpguts.HeaderValuesContainsToken(conv, "close")
	if major == 1 && minor == 0 {
		return hasClose || !httpguts.HeaderValuesContainsToken(conv, "keep-alive")
	}

	if hasClose && removeCloseHeader {
		header.Del("Connection")
	}

	return hasClose
}

// RFC 7234, section 5.4: Should treat
//
//	Pragma: no-cache
//
// like
//
//	Cache-Control: no-cache
func fixPragmaCacheControl(header http.Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}
