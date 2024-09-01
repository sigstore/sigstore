package alibaba

import (
	"context"
	"github.com/AliyunContainerService/ack-ram-tool/pkg/credentials/provider"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"time"
)

func init() {
	provider.DefaultLogger.SetSilentInfo(true)
}

type credentialForV2SDK struct {
	*provider.CredentialForV2SDK
	cp provider.CredentialsProvider
}

func getCredential() (credentials.Credential, error) {
	cp := provider.NewDefaultChainProvider(provider.DefaultChainProviderOptions{})
	cred := &credentialForV2SDK{
		cp: cp,
		CredentialForV2SDK: provider.NewCredentialForV2SDK(cp, provider.CredentialForV2SDKOptions{
			CredentialRetrievalTimeout: time.Second * 30,
		}),
	}

	return cred, nil
}

func (c *credentialForV2SDK) GetCredential() (*credentials.CredentialModel, error) {
	var token *string
	cred, err := c.cp.Credentials(context.TODO())
	if err != nil {
		return nil, err
	}
	if cred.SecurityToken != "" {
		token = tea.String(cred.SecurityToken)
	}
	return &credentials.CredentialModel{
		AccessKeyId:     tea.String(cred.AccessKeyId),
		AccessKeySecret: tea.String(cred.AccessKeySecret),
		SecurityToken:   token,
		BearerToken:     nil,
		Type:            c.GetType(),
	}, err
}
