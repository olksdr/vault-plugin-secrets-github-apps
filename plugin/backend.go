package gh

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/patrickmn/go-cache"
)

type backend struct {
	*framework.Backend

	httpClient *http.Client
	cache      *cache.Cache
}

// Factory returns a configured instance of the logical Backend
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend sets up the Backend object with all the required settings
// and return the reference to it
func Backend() *backend {
	b := &backend{
		httpClient: &http.Client{},
		cache:      cache.New(10*time.Minute, 15*time.Minute),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: framework.PathAppend(
			// provide paths to access the org and tokens
			pathsToken(b),
			[]*framework.Path{
				// configuration
				pathConfig(b),
			}),
	}
	return b
}

const backendHelp = `
The Github secrets backend is a backend which generated github access token.
It uses Github Apps (https://developer.github.com/v3/apps/) interface to retrieve the tokens
for the installed Github App on the requested organization.

After mounting this secrets engine, you can configure the credentials using the
"config/" endpoints. You can generate access tokens using "token/<organization name>" endpoint
`
