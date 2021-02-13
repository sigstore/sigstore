package x509pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func GenPrivKeyPEM() (*rsa.PrivateKey, error) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// TODO: The followinfg subj values should be gathered from
// a developers profile (likely something in ~/.config)
func GenerateCsr(keyBytes interface{}) ([]byte, error) {
	emailAddress := "johnsmith@example.com"
    subj := pkix.Name{
        CommonName:         "example.com",
        Country:            []string{"UK"},
        Province:           []string{"Wiltshire"},
        Locality:           []string{"Chippeham"},
        Organization:       []string{"Acme Inc"},
        OrganizationalUnit: []string{"OCTO"},
        ExtraNames: []pkix.AttributeTypeAndValue{
            {
                Type:  oidEmailAddress,
                Value: asn1.RawValue{
                    Tag:   asn1.TagIA5String,
                    Bytes: []byte(emailAddress),
                },
            },
        },
    }

    template := x509.CertificateRequest{
        Subject:            subj,
        SignatureAlgorithm: x509.SHA256WithRSA,
    }

    csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}), nil

}


// placeholder in case we need to dump to file (PEM)
// func savePEMKey(fileName string, key *rsa.PrivateKey) {
// 	outFile, err := os.Create(fileName)
// 	checkError(err)
// 	defer outFile.Close()

// 	var privateKey = &pem.Block{
// 		Type:  "PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(key),
// 	}

// 	err = pem.Encode(outFile, privateKey)
// 	checkError(err)
// }


//placeholder in case we need to dump to file
// func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
// 	asn1Bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
// 	checkError(err)

// 	var pemkey = &pem.Block{
// 		Type:  "PUBLIC KEY",
// 		Bytes: asn1Bytes,
// 	}

// 	pemfile, err := os.Create(fileName)
// 	checkError(err)
// 	defer pemfile.Close()

// 	err = pem.Encode(pemfile, pemkey)
// 	checkError(err)
// }

// func genPrivKeyPEM(key *rsa.PrivateKey) (*pem.Block, error) {
// 	var privateKey = &pem.Block{
// 		Type:  "PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(key),
// 	}
// 	return privateKey, nil
// }


// placeholder in case we need to dump to file
// func saveGobKey(fileName string, key interface{}) {
// 	outFile, err := os.Create(fileName)
// 	checkError(err)
// 	defer outFile.Close()

// 	encoder := gob.NewEncoder(outFile)
// 	err = encoder.Encode(key)
// 	checkError(err)
// }

