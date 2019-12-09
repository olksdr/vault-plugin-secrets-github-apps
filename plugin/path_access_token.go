package gh

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/context/ctxhttp"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	GITHUB_MACHINE_MAN_HEADER = "application/vnd.github.machine-man-preview+json"
	GITHUB_API_ENDPOINT       = "https://api.github.com"
)

type token struct {
	AccessToken string `json:"token"`
	ExpiresAt   string `json:"expires_at"`
}

type account struct {
	Login string `json:"login"`
}

type installation struct {
	account `json:"account"`
	ID      int `json:"id"`
}

func pathsToken(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("token/%s", framework.GenericNameRegex("organization")),
			Fields: map[string]*framework.FieldSchema{
				"organization": {
					Type:        framework.TypeString,
					Description: "Required. Name of the organization",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.accessTokenResponse,
				logical.CreateOperation: b.accessTokenResponse,
				logical.UpdateOperation: b.accessTokenResponse,
			},

			HelpSynopsis:    secretPathHelpSyn,
			HelpDescription: secretPathHelpDesc,
		},
		{
			Pattern: "token/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathOrgsList,
				logical.ListOperation: b.pathOrgsList,
			},
			HelpSynopsis:    orgsListHelpSyn,
			HelpDescription: orgsListHelpDesc,
		},
	}
}

func (b *backend) pathOrgsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var orgs []string
	v, found := b.cache.Get("orgs")
	if !found {
		jwt, err := generateLocalJWT(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		ins, err := b.getInstallations(ctx, jwt)
		if err != nil {
			return nil, err
		}

		for _, org := range ins {
			orgs = append(orgs, org.Login)
		}

		if len(orgs) > 0 {
			b.cache.Set("orgs", orgs, cache.DefaultExpiration)
		}

	} else {
		orgs = v.([]string)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"organizations": orgs,
		},
	}, nil
}

func (b *backend) accessTokenResponse(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	org := d.Get("organization").(string)

	var tok token
	v, found := b.cache.Get("access_token")
	if !found {
		t, err := b.getToken(ctx, org, req.Storage)
		if err != nil {
			return nil, err
		}
		// get the real struct
		tok = *t
		if t != nil && tok.AccessToken != "" {
			b.cache.Set("access_token", tok, cache.DefaultExpiration)
		}
	} else {
		tok = v.(token)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token":      tok.AccessToken,
			"expires_at": tok.ExpiresAt,
			"token_type": "token",
		},
	}, nil
}

func (b *backend) getInstallations(ctx context.Context, jwt string) ([]installation, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/app/installations", GITHUB_API_ENDPOINT), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	req.Header.Add("Accept", GITHUB_MACHINE_MAN_HEADER)

	res, err := ctxhttp.Do(ctx, b.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github responded with status: %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var installations []installation
	err = json.Unmarshal(body, &installations)
	if err != nil {
		return nil, err
	}
	return installations, nil
}

func (b *backend) newAccecssToken(ctx context.Context, id int, jwt string) (*token, error) {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/app/installations/%d/access_tokens", GITHUB_API_ENDPOINT, id), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	req.Header.Add("Accept", GITHUB_MACHINE_MAN_HEADER)

	res, err := ctxhttp.Do(ctx, b.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github responded with status: %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var token token
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// generateToken generates the local signed payload which is sent to Github
// and in response we get access token
func (b *backend) getToken(ctx context.Context, org string, s logical.Storage) (*token, error) {
	jwt, err := generateLocalJWT(ctx, s)
	if err != nil {
		return nil, err
	}

	installations, err := b.getInstallations(ctx, jwt)
	if err != nil {
		return nil, err
	}

	for _, ins := range installations {
		if ins.Login == org {
			return b.newAccecssToken(ctx, ins.ID, jwt)
		}
	}
	return &token{}, nil
}

// generateLocalJWT generates the local JWT which is used to sign the request to Github
// and fetch the access token for the specific organization
func generateLocalJWT(ctx context.Context, s logical.Storage) (string, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", fmt.Errorf("configuration missing")
	}

	now := time.Now()
	dar, _ := pem.Decode([]byte(cfg.PrivateKey))
	if dar == nil || dar.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("provided key has wrong type: %s", dar.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(dar.Bytes)
	if err != nil {
		return "", err
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Issuer:   fmt.Sprintf("%d", cfg.AppID),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Second * 600)),
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

const orgsListHelpSyn = `List organizations where the configured app is installed`
const orgsListHelpDesc = `
This path will return the list of the oranizations where the configured application
is installed and functioning. This response is cached for 10 minutes and if the app
was installed on the new organization, it will be available shortly after cache is expired
`
const secretPathHelpSyn = `Generate an access token under the specific organization`
const secretPathHelpDesc = `
This path will generate a new access token for accessing the GithubAP for the 
specific organization. Permissions associated with the token is configurated on app level
in the admin section of the Github UI. See the set of permissions (https://developer.github.com/v3/apps/permissions/)
which can be given to the application. This response is cached for 10 minutes.

Organization must be provided in following path "token/<organization name>", which will be used to check the active installations
and generated the token if the installation for the requested organization exists
`
