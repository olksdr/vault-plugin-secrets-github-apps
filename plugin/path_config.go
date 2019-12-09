package gh

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"private_key": {
				Type:        framework.TypeString,
				Description: "Private RSA key generated for the application: https://developer.github.com/apps/building-github-apps/authenticating-with-github-apps/#generating-a-private-key",
			},
			"app_id": {
				Type:        framework.TypeInt,
				Description: "GitHub App's identifier, which can be found on the page of the created app",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
			logical.DeleteOperation: b.pathConfigDelete,
		},

		ExistenceCheck: b.pathConfigExistenceCheck,

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return cfg != nil, err
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")
	return nil, err
}

// pathConfigRead reads the config from the logical storage
// and returns the non-sensitive data about the current configuration:
// 		`app_id`   - Github app identifier
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"app_id": cfg.AppID,
		},
	}, nil
}

// pathConfigWrite writes the new provided configuration into the logical storage for later usage
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	privateKey, ok := data.GetOk("private_key")
	if ok {
		cfg.PrivateKey = privateKey.(string)
	}

	appID, ok := data.GetOk("app_id")
	if ok {
		cfg.AppID = appID.(int)
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

type config struct {
	PrivateKey string
	AppID      int
}

// getConfig retrieves the config for this backend from the logical storage
func getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	var cfg config
	cfgRaw, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if cfgRaw == nil {
		return nil, nil
	}

	if err := cfgRaw.DecodeJSON(&cfg); err != nil {
		return nil, err
	}

	return &cfg, err
}

const pathConfigHelpSyn = `
Configure the Github secrets backend
`

const pathConfigHelpDesc = `
The Github secrets backend requires credentials to generate
and request the tokens. This endpoint is used to configure those credentials
as well as default values for the backend in general.
`
