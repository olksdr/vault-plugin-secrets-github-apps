package gh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultLeaseTTLHr = 1 * time.Hour
	maxLeaseTTLHr     = 12 * time.Hour
)

type RoundTripFn func(req *http.Request) *http.Response

func (f RoundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func NewTestClient(fn RoundTripFn) *http.Client {
	return &http.Client{
		Transport: RoundTripFn(fn),
	}
}

func getTestBackend(tb testing.TB) (logical.Backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = logging.NewVaultLogger(log.Trace)
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLHr,
		MaxLeaseTTLVal:     maxLeaseTTLHr,
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	bac := b.(*backend)
	bac.httpClient = NewTestClient(func(req *http.Request) *http.Response {

		var body string
		var statusCode int
		switch req.URL.String() {
		case fmt.Sprintf("%s/app/installations/12345/access_tokens", GITHUB_API_ENDPOINT):
			body = `{"token": "v1.95e975e1305082871a18677ccdfc19286b5c10a2", "expires_at": "2019-12-04T09:21:14Z"}`
			statusCode = http.StatusCreated
		case fmt.Sprintf("%s/app/installations", GITHUB_API_ENDPOINT):
			body = `[{"account": {"login": "ownername"}, "id": 12345}]`
			statusCode = http.StatusOK
		}

		return &http.Response{
			StatusCode: statusCode,
			Body:       ioutil.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}
	})
	return bac, config.StorageView
}
