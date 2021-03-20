/*
Copyright © 2021 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package keymgmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

func GeneratePrivateKey(algorithm string) (interface{}, interface{}, error) {
	var err error = nil
	var key interface{}
	// Allow algorithm agility if different projects have certain FIPS like compliance requirements
	switch algorithm {
	case "rsa2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case "ecdsaP224":
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "ecdsaP256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsaP384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsaP521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = errors.New("Unsupported algorithm: " + algorithm)
	}
	pub, err := getPublicKey(key)
	return key, pub, err
}

func getPublicKey(priv interface{}) (interface{}, error) {
	var err error = nil
	var pub interface{}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	// The below would never happen (unless upstream crypto is broken, but lets log it anyway)
	default:
		err = errors.New("error generating public key" )
	}

	return pub, err
}
