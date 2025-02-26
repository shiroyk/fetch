package fetch

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

var encodings = []string{"gzip", "deflate", "br"}

// Decoder decode Content-Encoding from HTTP header (gzip, deflate, br) encodings.
type Decoder http.Transport

func (t *Decoder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		req.Header["Accept-Encoding"] = encodings
	}
	response, err := (*http.Transport)(t).RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return DecodeResponse(response)
}

type warpReadCloser struct {
	Reader io.Reader
	Closer func() error
}

func (r *warpReadCloser) Read(p []byte) (n int, err error) { return r.Reader.Read(p) }
func (r *warpReadCloser) Close() error                     { return r.Closer() }

// DecodeResponse decode Content-Encoding from HTTP header (gzip, deflate, br) encodings.
func DecodeResponse(res *http.Response) (*http.Response, error) {
	// In the order decompressed
	encoding := res.Header.Get("Content-Encoding")
	if encoding == "" {
		return res, nil
	}
	var (
		body = res.Body
		err  error
	)
	for _, encode := range strings.Split(encoding, ",") {
		switch strings.TrimSpace(encode) {
		case "deflate":
			body, err = zlib.NewReader(body)
		case "gzip":
			body, err = gzip.NewReader(body)
		case "br":
			body = &warpReadCloser{brotli.NewReader(body), body.Close}
		default:
			err = fmt.Errorf("unsupported compression type %s", encode)
		}
		if err != nil {
			return nil, err
		}
		res.Body = body
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Uncompressed = true
	}
	return res, nil
}
