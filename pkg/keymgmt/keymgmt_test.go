package keymgmt

import (
"testing"
)

func TestGenerateKeys(t *testing.T) {
	algs := []string{"1024", "2048", "3072", "P224", "P256", "P384", "P521"}

	for _, alg := range algs {
		_, _, err := GeneratePrivateKey(alg)

		if err != nil {
			t.Errorf("Key generation failed: %s\n", err)
		}
	}
}
