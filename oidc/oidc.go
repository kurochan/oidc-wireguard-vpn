package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/okzk/go-ciba"
	"go.uber.org/zap"
)

type Metadata struct {
	Issuer                            string `json:"issuer"`
	TokenEndpoint                     string `json:"token_endpoint"`
	BackchannelAuthenticationEndpoint string `json:"backchannel_authentication_endpoint"`
	IntrospectionEndpoint             string `json:"introspection_endpoint"`
}

type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
}

type OIDC struct {
	Config Config
}

func getOIDCMetaData(metadataEndpoint string) (*Metadata, error) {
	req, err := http.NewRequest(http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return nil, err
	}
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var metadata Metadata
	if err := json.NewDecoder(res.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (o *OIDC) Authenticate(uid string, code string) (int, error) {
	metadata, err := getOIDCMetaData(o.Config.Endpoint)
	if err != nil {
		zap.L().Error("metadata error", zap.Error(err))
		return -1, err
	}

	client := ciba.NewClient(
		metadata.Issuer,
		metadata.BackchannelAuthenticationEndpoint,
		metadata.TokenEndpoint,
		"openid",
		o.Config.ClientID,
		o.Config.ClientSecret,
	)
	ctx := context.Background()
	token, err := client.Authenticate(ctx, ciba.LoginHint(uid), ciba.UserCode(code))
	if err != nil {
		zap.L().Warn(fmt.Sprintf("authenticate error: %s", uid), zap.Error(err))
		return -1, err
	}
	zap.L().Info(fmt.Sprintf("authenticate success: %s, %d", uid, token.ExpiresIn))
	return token.ExpiresIn, nil
}
