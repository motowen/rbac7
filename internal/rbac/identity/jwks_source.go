package identity

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

type RemoteJWKSKeySource struct {
	jwksURL string
	client  *http.Client
}

func NewRemoteJWKSKeySource(jwksURL string, client *http.Client) *RemoteJWKSKeySource {
	if client == nil {
		client = http.DefaultClient
	}
	return &RemoteJWKSKeySource{jwksURL: jwksURL, client: client}
}

func (s *RemoteJWKSKeySource) PublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	if s.jwksURL == "" {
		return nil, fmt.Errorf("%w: jwks url is empty", ErrKeyNotFound)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build jwks request", ErrKeyNotFound)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch jwks", ErrKeyNotFound)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: jwks status %d", ErrKeyNotFound, resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: decode jwks", ErrKeyNotFound)
	}

	for _, key := range doc.Keys {
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		if key.KeyType != "RSA" || key.Modulus == "" || key.Exponent == "" {
			continue
		}
		publicKey, err := rsaPublicKeyFromJWK(key)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}

	return nil, ErrKeyNotFound
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyID    string `json:"kid"`
	KeyType  string `json:"kty"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

func rsaPublicKeyFromJWK(key jwkKey) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil {
		return nil, fmt.Errorf("%w: decode modulus", ErrKeyNotFound)
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil {
		return nil, fmt.Errorf("%w: decode exponent", ErrKeyNotFound)
	}
	if len(exponentBytes) == 0 {
		return nil, fmt.Errorf("%w: exponent is empty", ErrKeyNotFound)
	}

	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("%w: exponent is invalid", ErrKeyNotFound)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}, nil
}
