package alibaba

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"testing"
)

const resourceURIForTest = "alibabakms://kms.cn-hangzhou.aliyuncs.com/i-xxx/55dd1500-0c2b-49be-foo/versions/0b334fad-f59a-4376-bar"

func Test_validReference(t *testing.T) {
	type args struct {
		ref string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				ref: "alibabakms://kms.cn-hangzhou.aliyuncs.com/i-xxx/55dd1500-0c2b-49be-foo/versions/0b334fad-f59a-4376-bar",
			},
			wantErr: false,
		},
		{
			name: "valid 2",
			args: args{
				ref: "alibabakms://kms.cn-hangzhou.aliyuncs.com//alias/foobar",
			},
			wantErr: false,
		},
		{
			name: "invalid 1",
			args: args{
				ref: "foobar",
			},
			wantErr: true,
		},
		{
			name: "invalid 2",
			args: args{
				ref: "alibabakms://",
			},
			wantErr: true,
		},
		{
			name: "invalid 3",
			args: args{
				ref: "alibabakms://kms.cn-hangzhou.aliyuncs.com/",
			},
			wantErr: true,
		},
		{
			name: "invalid 4",
			args: args{
				ref: "alibabakms://kms.cn-hangzhou.aliyuncs.com/x/y/z",
			},
			wantErr: true,
		},
		{
			name: "invalid 5",
			args: args{
				ref: "alibabakms://kms.cn-hangzhou.aliyuncs.com/x/y/z/versions/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validReference(tt.args.ref)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_newAliClient(t *testing.T) {
	client, err := newAliClient(context.TODO(), resourceURIForTest)
	if err != nil {
		t.Errorf("newAliClient() error = %v", err)
	}
	if client == nil {
		t.Errorf("newAliClient() client is nil")
	}
}

func genGetPublicKeyResp(t *testing.T, key crypto.PublicKey) kms20160120.GetPublicKeyResponseBody {
	publicKeyBytes := genPemPublicKey(t, key)
	resp := kms20160120.GetPublicKeyResponseBody{
		KeyId:        nil,
		KeyVersionId: nil,
		PublicKey:    tea.String(string(publicKeyBytes)),
		RequestId:    nil,
	}
	return resp
}

func genPemPublicKey(t *testing.T, key crypto.PublicKey) []byte {
	ecdsaPub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Error("failed to cast public key to esdsa public key")
	}
	data, err := x509.MarshalPKIXPublicKey(ecdsaPub)
	if err != nil {
		t.Errorf("failed to marshal public key: %v", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	return pem.EncodeToMemory(block)
}

func genPublicKey(t *testing.T) crypto.PublicKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("err is not nil: %+v", err)
	}

	ecdsaPub, ok := privKey.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Error("failed to cast public key to esdsa public key")
	}
	return ecdsaPub
}

func Test_parseReference(t *testing.T) {
	type args struct {
		resourceID string
	}
	tests := []struct {
		name    string
		args    args
		wantRef *Reference
		wantErr bool
	}{
		{
			name: "valid 1",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com/i-xxx/55dd1500-0c2b-49be-foo/versions/0b334fad-f59a-4376-bar",
			},
			wantRef: &Reference{
				endpoint:     "kms.cn-hangzhou.aliyuncs.com",
				instanceId:   "i-xxx",
				keyId:        "55dd1500-0c2b-49be-foo",
				keyVersionId: "0b334fad-f59a-4376-bar",
				aliasName:    "",
			},
			wantErr: false,
		},
		{
			name: "valid 2",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com/i-xxx/alias/foobar",
			},
			wantRef: &Reference{
				endpoint:     "kms.cn-hangzhou.aliyuncs.com",
				instanceId:   "i-xxx",
				keyId:        "",
				keyVersionId: "",
				aliasName:    "alias/foobar",
			},
			wantErr: false,
		},
		{
			name: "valid 3",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com//55dd1500-0c2b-49be-foo/versions/0b334fad-f59a-4376-bar",
			},
			wantRef: &Reference{
				endpoint:     "kms.cn-hangzhou.aliyuncs.com",
				instanceId:   "",
				keyId:        "55dd1500-0c2b-49be-foo",
				keyVersionId: "0b334fad-f59a-4376-bar",
				aliasName:    "",
			},
			wantErr: false,
		},
		{
			name: "valid 4",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com//alias/foobar",
			},
			wantRef: &Reference{
				endpoint:     "kms.cn-hangzhou.aliyuncs.com",
				instanceId:   "",
				keyId:        "",
				keyVersionId: "",
				aliasName:    "alias/foobar",
			},
			wantErr: false,
		},
		{
			name: "invalid 1",
			args: args{
				resourceID: "foobar",
			},
			wantErr: true,
		},
		{
			name: "invalid 2",
			args: args{
				resourceID: "alibabakms://",
			},
			wantErr: true,
		},
		{
			name: "invalid 3",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com/",
			},
			wantErr: true,
		},
		{
			name: "invalid 4",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com/x/y/z",
			},
			wantErr: true,
		},
		{
			name: "invalid 5",
			args: args{
				resourceID: "alibabakms://kms.cn-hangzhou.aliyuncs.com/x/y/z/versions/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRef, err := parseReference(tt.args.resourceID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equalf(t, tt.wantRef, gotRef, "parseReference(%v)", tt.args.resourceID)
		})
	}
}
