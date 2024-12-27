package auth

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/99designs/keyring"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

type Keyring_Azure struct {
	client *azsecrets.Client
}

// create a hash of a key so that Azure can access it by URI
// and avoid namespace/user collisions by using a sanitized version as prefix
func hash(text string) string {
	hash := md5.Sum([]byte(text))
	sanitized := regexp.MustCompile("[^a-zA-Z0-9]").ReplaceAllString(text, "-")
	return sanitized + "-" + hex.EncodeToString(hash[:])
}

func (ka *Keyring_Azure) Connect(keyVaultURI string) error {

	// Create a credential using the NewDefaultAzureCredential type.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to obtain a credential: %v", err)
	}

	// Establish a connection to the Key Vault
	client, err := azsecrets.NewClient(keyVaultURI, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to establish a connection to the Azure key vault: %v", err)
	}

	ka.client = client
	return nil
}

func (ka Keyring_Azure) Get(key string) (keyring.Item, error) {
	// Get a secret. An empty string version gets the latest version of the secret.
	version := ""
	resp, err := ka.client.GetSecret(context.TODO(), hash(key), version, nil)
	if err != nil {
		return keyring.Item{}, fmt.Errorf("failed to get the secret: %v", err)
	}

	return keyring.Item{
		// List is returned as a set of URIs prefixed by vault URI and /secret/
		Key:  *resp.Tags["key"],
		Data: []byte(*resp.Value),
	}, nil
}

// No-op
func (ka Keyring_Azure) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}

func (ka Keyring_Azure) Set(item keyring.Item) error {
	value := string(item.Data)
	// Create a secret
	params := azsecrets.SetSecretParameters{Value: &value,
		SecretAttributes: &azsecrets.SecretAttributes{},
		Tags:             map[string]*string{"key": &item.Key}}
	_, err := ka.client.SetSecret(context.TODO(), hash(item.Key), params, nil)
	if err != nil {
		return fmt.Errorf("failed to create a secret: %v", err)
	}
	return nil
}

func (ka Keyring_Azure) Remove(key string) error {
	// Delete a secret. DeleteSecret returns when Key Vault has begun deleting the secret.
	// That can take several seconds to complete, so it may be necessary to wait before
	// performing other operations on the deleted secret.
	_, err := ka.client.DeleteSecret(context.TODO(), hash(key), nil)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %v", err)
	}
	return nil
}

func (ka Keyring_Azure) Purge(key string) error {
	// Purge a deleted secret. PurgeDeletedSecret - The purge deleted secret operation removes the
	// secret permanently, without the possibility of recovery. This operation can only be enabled
	// on a soft-delete enabled vault. This operation requires the secrets/purge permission
	_, err := ka.client.PurgeDeletedSecret(context.TODO(), hash(key), nil)
	if err != nil {
		return fmt.Errorf("failed to purge secret: %v", err)
	}
	return nil
}

func (ka Keyring_Azure) Keys() ([]string, error) {
	// List secrets
	var secrets []string
	pager := ka.client.NewListSecretsPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, secret := range page.Value {
			secrets = append(secrets, *secret.Tags["key"])
		}
	}
	return secrets, nil
}
