package auth

import (
	"os"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
)

// Requires:
// * admin privileges to an Azure Key Vault with soft delete enabled
// * environment variable AZURE_KEY_VAULT set to the key vault name
func TestAuth_Azure(t *testing.T) {
	keys_azure := Keyring_Azure{}

	item := keyring.Item{
		Key:  "test",
		Data: []byte("secret"),
	}

	// Try to connect to a vault I don't have access to
	keys_azure.Connect("https://not-my-vault.vault.azure.net")
	assert.Error(t, keys_azure.Set(item), "not authorized")

	// Connect to a vault I have access to
	keys_azure.Connect(os.Getenv("AZURE_KEY_VAULT"))

	// List keys
	keys, err := keys_azure.Keys()
	assert.NoError(t, err)
	originalLen := len(keys)
	originalKeys := keys

	// Add a key
	assert.NoError(t, keys_azure.Set(item))
	// List keys again
	keys, err = keys_azure.Keys()
	assert.NoError(t, err)
	assert.Contains(t, keys, item.Key)

	// Get a key
	item_test, err := keys_azure.Get(item.Key)
	assert.NoError(t, err)
	assert.Equal(t, item, item_test)

	// Delete a key
	err = keys_azure.Remove(item.Key)
	assert.NoError(t, err)

	// Purge from keyvault
	time.Sleep(5 * time.Second)
	err = keys_azure.Purge(item.Key)
	assert.NoError(t, err)

	// List keys again
	keys, err = keys_azure.Keys()
	assert.NoError(t, err)
	assert.Len(t, keys, originalLen)
	assert.Equal(t, originalKeys, keys)

}

func TestAuth_Azure_ComplexKey(t *testing.T) {
	keys_azure := Keyring_Azure{}

	item := keyring.Item{
		Key:  "test/a/complex|key|with&!special@characters",
		Data: []byte("secret"),
	}

	// Connect to a vault I have access to
	keys_azure.Connect(os.Getenv("AZURE_KEY_VAULT"))

	// List keys
	keys, err := keys_azure.Keys()
	assert.NoError(t, err)
	originalLen := len(keys)
	originalKeys := keys

	// Add a key
	assert.NoError(t, keys_azure.Set(item))
	// List keys again
	keys, err = keys_azure.Keys()
	assert.NoError(t, err)
	assert.Contains(t, keys, item.Key)

	// Get a key
	item_test, err := keys_azure.Get(item.Key)
	assert.NoError(t, err)
	assert.Equal(t, item, item_test)

	// Delete a key
	err = keys_azure.Remove(item.Key)
	assert.NoError(t, err)

	// Purge from keyvault
	time.Sleep(5 * time.Second)
	err = keys_azure.Purge(item.Key)
	assert.NoError(t, err)

	// List keys again
	keys, err = keys_azure.Keys()
	assert.NoError(t, err)
	assert.Len(t, keys, originalLen)
	assert.Equal(t, originalKeys, keys)

}
