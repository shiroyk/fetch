package fetch

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequest(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=iso-8859-9")
		switch r.Method {
		case http.MethodPut:
			if token := r.Header.Get("Authorization"); token != "1919810" {
				t.Errorf("unexpected token %s", token)
			}
		case http.MethodGet:
			_, err := fmt.Fprint(w, "114514")
			require.NoError(t, err)
			return
		}

		if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
			file, _, err := r.FormFile("file")
			require.NoError(t, err)

			body, err := io.ReadAll(file)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(body))
			require.NoError(t, err)
		} else {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(body))
			require.NoError(t, err)
		}
	})

	fetch := newTestFetcher()

	mpBytes, mpwHeader := createMultiPart(t, map[string]any{
		"key":  "foo",
		"file": []byte{226, 153, 130, 239, 184, 142},
	})

	jsonData := struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{Key: "foo", Value: "bar"}

	token := map[string]string{"Authorization": "1919810"}

	testCase := []struct {
		method string
		body   any
		header map[string]string
		want   string
	}{
		{http.MethodGet, nil, nil, "114514"},
		{
			http.MethodPost, url.Values{"key": {"holy"}}.Encode(),
			map[string]string{"Content-Type": "application/x-www-form-url"},
			"key=holy",
		},
		{http.MethodPost, []byte{226, 153, 130, 239, 184, 142}, nil, "♂︎"},
		{http.MethodPost, strings.NewReader("fa"), nil, "fa"},
		{http.MethodPost, bytes.NewBuffer(mpBytes), mpwHeader, "♂︎"},
		{http.MethodPost, bytes.NewReader(mpBytes), mpwHeader, "♂︎"},
		{http.MethodPost, jsonData, nil, `{"key":"foo","value":"bar"}`},
		{http.MethodPut, jsonData, token, `{"key":"foo","value":"bar"}`},
	}

	for _, useTLS := range []bool{false, true} {
		var ts *httptest.Server
		if useTLS {
			ts = httptest.NewTLSServer(h)
			fetch.Client = ts.Client()
		} else {
			ts = httptest.NewServer(h)
		}

		t.Run(fmt.Sprintf("useTLS=%v", useTLS), func(t *testing.T) {
			defer ts.Close()
			for _, r := range testCase {
				switch b := r.body.(type) {
				// rewrite bytes
				case *bytes.Buffer:
					b.Write(mpBytes)
				case *bytes.Reader:
					b.Reset(mpBytes)
				case *strings.Reader:
					b.Reset("fa")
				}
				req, err := NewRequest(r.method, ts.URL, r.body, r.header)
				require.NoError(t, err)

				res, err := doString(fetch, req)
				require.NoError(t, err)
				assert.Equal(t, r.want, res)
			}
		})
	}
}

func createMultiPart(t *testing.T, data map[string]any) ([]byte, map[string]string) {
	buf := &bytes.Buffer{}
	mpw := multipart.NewWriter(buf)
	for k, v := range data {
		if f, ok := v.([]byte); ok {
			// Creates a new form-data header with the provided field name and file name.
			fw, err := mpw.CreateFormFile(k, "blob")
			require.NoError(t, err)
			// Write bytes to the part
			if _, err := fw.Write(f); err != nil {
				t.Fatal(err)
			}
		} else {
			// Write string value
			if err := mpw.WriteField(k, fmt.Sprintf("%v", v)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := mpw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), map[string]string{"Content-Type": mpw.FormDataContentType()}
}

var templateTestCase = []struct{ template, want string }{
	{`CONNECT {{.url}}`, ""},
	{`GET {{.url}} HTTP/1.1`, ""},
	{`{{.url}}?page=1`, "page=1"},
	{`{{.url}}{{if gt .page 1}}?page={{.page}}{{end}}`, "page=2"},
	{`{{.url}}?key={{.data.key}}`, "key=foo"},
	{`POST {{.url}}
Content-Type: application/json

{{ data "json" }}`, `{"key":"foo"}`},
	{`POST {{.url}}
Content-Type: application/x-www-form-urlencoded

{{ data "form" }}`, `foo`},
	{`POST {{.url}} HTTP/2.0
Pragma: no-cache
Content-Type: application/octet-stream
Connection: close

{{ data "image" }}`, "image/png"},
	{`POST {{.url}} HTTP/1.0
Content-Type: multipart/form-data; boundary=X-123456

--X-123456
Content-Disposition: form-data; name="key"

foo
--X-123456
Content-Disposition: form-data; name="file"; filename="test.png"
Content-Type: image/png

{{ data "image" }}
--X-123456--`, "foo-test.png-image/png"},
}

func TestReadRequest(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		var body []byte
		contentType := r.Header.Get("Content-Type")
		switch contentType {
		case "application/octet-stream":
			b, _ := io.ReadAll(r.Body)
			body = []byte(http.DetectContentType(b))
		case "application/x-www-form-urlencoded":
			body = []byte(r.FormValue("key"))
		case "multipart/form-data; boundary=X-123456":
			if err := r.ParseMultipartForm(DefaultMaxBodySize); err != nil {
				t.Fatal(err)
			}
			file, fh, err := r.FormFile("file")
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(file)
			body = []byte(fmt.Sprintf("%s-%s-%s", r.FormValue("key"), fh.Filename, http.DetectContentType(data)))
		default:
			if r.Method == http.MethodGet {
				require.NoError(t, r.ParseForm())
				body = []byte(r.Form.Encode())
			} else {
				body, _ = io.ReadAll(r.Body)
			}
		}
		_, _ = w.Write(body)
	})

	f := newTestFetcher()
	tplFuncs := templateFuncs()

	ts := httptest.NewServer(h)
	arg := map[string]any{
		"url":  ts.URL,
		"page": 2,
		"data": map[string]any{
			"key": "foo",
		},
	}

	for _, c := range templateTestCase {
		tpl, err := template.New("url").Funcs(tplFuncs).Parse(c.template)
		require.NoError(t, err)
		var data bytes.Buffer
		require.NoError(t, tpl.Execute(&data, arg))
		req, err := ReadRequest(data.String())
		require.NoError(t, err)

		res, err := doString(f, req)
		require.NoError(t, err)
		assert.Equal(t, c.want, res)
	}
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"data": func(key string) string {
			switch key {
			case "json":
				return `{"key":"foo"}`
			case "form":
				return `key=foo&value=bar`
			case "image":
				return string([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
			default:
				return ""
			}
		},
	}
}

func newTestFetcher() *Fetch {
	return NewFetch(Options{
		MaxBodySize:    DefaultMaxBodySize,
		RetryHTTPCodes: DefaultRetryHTTPCodes,
		Timeout:        DefaultTimeout,
	})
}
