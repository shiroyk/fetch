package http2

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	extNet = os.Getenv("EXTNET")
)

func TestFingerPrint(t *testing.T) {
	if extNet == "" {
		t.Skip("skipping external network test")
	}

	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	assert.NoError(t, err)
	req.Header = http.Header{
		"Sec-Ch-Ua":          {`"Not.A/Brand";v="8", "Chromium";v="111", "Google Chrome";v="111"`},
		"Sec-Ch-Ua-Platform": {`"Windows"`},
		"Dnt":                {"1"},
		"User-Agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36"},
		"Accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":     {"none"},
		"Sec-Fetch-Mode":     {"navigate"},
		"Sec-Fetch-User":     {"?1"},
		"Sec-Fetch-Dest":     {"document"},
		"Accept-Encoding":    {"gzip, deflate, br"},
		"Accept-Language":    {"en,en_US;q=0.9"},
	}

	transport := http.DefaultTransport.(*http.Transport)
	_ = ConfigureTransport(transport, Options{
		HeaderOrder: []string{
			"sec-ch-ua", "sec-ch-ua-platform", "dnt",
			"user-agent", "accept", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"accept-encoding", "accept-language",
		},
		PHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		Settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingMaxConcurrentStreams, Val: 1000},
			{ID: SettingInitialWindowSize, Val: 6291456},
			{ID: SettingMaxHeaderListSize, Val: 262144},
		},
		WindowSizeIncrement: 15663105,
		GetTlsClientHelloSpec: func() *tls.ClientHelloSpec {
			spec, _ := tls.UTLSIdToSpec(tls.HelloChrome_102)
			return &spec
		},
	})

	res, err := transport.RoundTrip(req)
	require.NoError(t, err)

	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var data map[string]any
	require.NoError(t, json.Unmarshal(b, &data))

	assert.Equal(t, data["http_version"], NextProtoTLS)

	if fp, ok := data["tls"].(map[string]any); ok {
		assert.Equal(t, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0", fp["ja3"])
		assert.Equal(t, "cd08e31494f9531f560d64c695473da9", fp["ja3_hash"])
		assert.Equal(t, "GREASE-772-771|2-1.1|GREASE-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-21-23-27-35-43-45-5-51-65281-GREASE-GREASE", fp["peetprint"])
		assert.Equal(t, "22a4f858cc83b9144c829ca411948a88", fp["peetprint_hash"])
	} else {
		assert.False(t, ok, data)
	}
	if fp, ok := data["http2"].(map[string]any); ok {
		assert.Equal(t, "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p", fp["akamai_fingerprint"])
		assert.Equal(t, "a345a694846ad9f6c97bcc3c75adbe26", fp["akamai_fingerprint_hash"])
	} else {
		assert.False(t, ok, data)
	}
}
