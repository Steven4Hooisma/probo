// Copyright (c) 2025-2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package coredata

import (
	"encoding"
	"fmt"
)

type ConnectorProtocol string

const (
	ConnectorProtocolOAuth2 ConnectorProtocol = "OAUTH2"
	ConnectorProtocolAPIKey ConnectorProtocol = "API_KEY"
	// ConnectorProtocolPrivateKeyJWT authenticates by signing a short-lived
	// client assertion with a customer-held private key and exchanging it for
	// a bearer token (RFC 7523). Unlike API_KEY the stored credential never
	// leaves Probo on the wire, and unlike OAUTH2 there is no user-facing
	// authorization step. Apple Business Manager requires it.
	ConnectorProtocolPrivateKeyJWT ConnectorProtocol = "PRIVATE_KEY_JWT"
)

var (
	_ fmt.Stringer             = ConnectorProtocol("")
	_ encoding.TextMarshaler   = ConnectorProtocol("")
	_ encoding.TextUnmarshaler = (*ConnectorProtocol)(nil)
)

func ConnectorProtocols() []ConnectorProtocol {
	return []ConnectorProtocol{
		ConnectorProtocolOAuth2,
		ConnectorProtocolAPIKey,
		ConnectorProtocolPrivateKeyJWT,
	}
}

func (v ConnectorProtocol) IsValid() bool {
	switch v {
	case
		ConnectorProtocolOAuth2,
		ConnectorProtocolAPIKey,
		ConnectorProtocolPrivateKeyJWT:
		return true
	}

	return false
}

func (v ConnectorProtocol) String() string {
	return string(v)
}

func (v ConnectorProtocol) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

func (v *ConnectorProtocol) UnmarshalText(text []byte) error {
	val := ConnectorProtocol(text)
	if !val.IsValid() {
		return fmt.Errorf("invalid ConnectorProtocol value: %q", string(text))
	}

	*v = val

	return nil
}
