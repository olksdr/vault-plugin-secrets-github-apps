Vault Plugin: Github Apps Secrets Backend
-----------------------

This is a standalone backend plugin for use with [Hashicorp Vault](https://github.com/hashicorp/vault). This plugin generates
auth tokens for the installed [applications](https://developer.github.com/v3/apps/) on the managed organizations.

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html) and is meant to work with Vault. 
This guide assumes you have already installed Vault and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).


### Building

Running `make` in the rootdirectory of this project should generate a `vault-plugin-secrets-github-apps` binary.


### Registration

To register this plugin with Vault, first copy the binary to the plugin directory configured for your 
running instance of Vault, then register the plugin with a command similar to this:

```bash
$ vault plugin register \
      -sha256="$(sha256sum vault-plugin-secrets-github-apps | cut -d " " -f1)" \
      secret \
      vault-plugin-secrets-github-apps
```

See the [plugin registration docs](https://www.vaultproject.io/docs/plugin/index.html) for more details.


### Usage

Once the plugin is registered as above, you can enable it on a given path:

```bash
$ vault secrets enable --path="gh" vault-plugin-secrets-github-apps
```

Then you can configure the access credentials, for this you need to find out the Application id and the genereated private key:

```bash
$ vault write gh/config app_id='12345'  private_key=@private.key
```

After plugin is enabled and configured you can get the list of the organizations where the app installed:

```bash
$ vault read gh/token
Key              Value
---              -----
organizations    [ownername]

```

And the token for this installation:

```bash
 $ vault read gh/token/ownername
Key           Value
---           -----
expires_at    2019-12-07T16:14:48Z
token         v1.d6babb68681d444b8070b30f222222ffffff9999
token_type    token
```

This token then can be used to query Github [API](https://developer.github.com/v3/apps/available-endpoints/), according to the permissions
granted to the application this token for issued for. 
**Note**: for using this token you need to [provide the custom media type](https://developer.github.com/v3/apps/#get-a-single-github-app) 
in `Accept` header: `application/vnd.github.machine-man-preview+json`

Use `vault path-help gh` to see full documentation on the options available on each endpoint.
