package crypto

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"net/http"
	"os"
	"strings"
)

type vaultClient struct {
	apiClient *api.Client
}

// the vault client requires two environment variables to retrieve secrets: VAULT_ADDR, VAULT_TOKEN
// instead of acting as an encrypter, the vault client instead acts as a secret retriever
// instead of the decrypt method taking in a ciphertext, it takes in the path to where the secret exists
func createVaultClient() (client *vaultClient, err error) {
	var vaultAddress, vaultToken string
	vaultAddress = os.Getenv("VAULT_ADDR")
	vaultToken = os.Getenv("VAULT_TOKEN")

	if len(vaultAddress) > 0 && len(vaultToken) > 0 {
		var apiClient *api.Client
		if apiClient, err = api.NewClient(&api.Config{Address: vaultAddress, HttpClient: &http.Client{}}); err == nil {
			client = &vaultClient{apiClient: apiClient}
			client.apiClient.SetToken(vaultToken)
		}
	} else {
		err = fmt.Errorf("must supply the address and authentication to your vault with the VAULT_ADDR and VAULT_TOKEN environment variables")
	}

	return client, err
}

// vault is read-only
func (c *vaultClient) Encrypt(path string) (value string, err error) {
	return "", fmt.Errorf("vault only supported for secret reading")
}

// input comes in the form of [secret/data/(subpath);(key)]
// secrets in vault are stored on a path in a key-value pair. The decrypt method returns the value corresponding to the key
func (c *vaultClient) Decrypt(path string) (value string, err error) {
	if len(path) > 0 {
		if strings.Index(path, ";") > 0 {

			var secretPath = path[0:strings.Index(path, ";")]
			var secretKey = path[strings.Index(path, ";")+1:]

			var data *api.Secret
			if data, err = c.apiClient.Logical().Read(secretPath); err == nil {
				if data != nil {

					for key, keyValue := range data.Data {
						switch v := keyValue.(type) {
						case string:
							if key == secretKey {
								value = v
							}
						case map[string]interface{}:
							for subKey, subKeyValue := range v {
								if subKey == secretKey {
									var ok bool
									value, ok = subKeyValue.(string)
									if !ok {
										err = fmt.Errorf("secret did not appear to be a string [%s]", path)
									}
								}
							}
						default:
							err = fmt.Errorf("unrecognized type [%v]", v)
						}
					}
				} else {
					err = fmt.Errorf("could not find data for [%s]", path)
				}
			}
		}

	} else {
		err = fmt.Errorf("empty secret path")
	}

	if len(value) == 0 && err == nil {
		err = fmt.Errorf("failed to find [%s]", path)
	}

	return value, err
}
