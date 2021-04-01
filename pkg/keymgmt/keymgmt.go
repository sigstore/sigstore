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
	var err error
	var key interface{}
	// Allow algorithm agility if different projects have certain FIPS like compliance requirements
	switch algorithm {
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
	if err != nil {
		return nil, nil, err
	}

	pub, err := getPublicKeyBytes(key)
	if err != nil {
		return nil, nil, err
	}

	return key, pub, err
}

func getPublicKeyBytes(priv interface{}) (interface{}, error) {
	var err error
	var pub interface{}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		err = errors.New("error generating public key" )
	}
	if err != nil {
		panic("error creating pubkey")
	}

	return pub, err
}

