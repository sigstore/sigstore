package keymgmt

import (
"testing"
)

func TestGenerateKeys(t *testing.T) {
	algs := []string{"rsa2048", "rsa3072", "ecdsaP224", "ecdsaP256", "ecdsaP384", "ecdsaP521"}

	for _, alg := range algs {
		_, _, err := GeneratePrivateKey(alg)

		if err != nil {
			t.Errorf("Key generation failed: %s\n", err)
		}
	}
}
