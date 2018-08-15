package jwt

import (
  "encoding/json"
  "errors"
  "github.com/hashicorp/errwrap"
  "strings"
  "time"
)

type Token struct {
  headerBytes  []byte
  Header       TokenHeader
  payloadBytes []byte
  Payload      TokenPayload
  signature    []byte
}

type TokenOptions struct {
  Algorithm string
  Type      string
  KeyId     string

  Issuer          string
  Audience        string
  Subject         string
  AuthorizedParty string
  IssuedAt        time.Time
  ExpiresAt       time.Time
  NotBefore       time.Time

  Claims map[string]interface{}
}

type SigningFunc = func([]byte) ([]byte, error)
type VerifyFunc = func([]byte, []byte) error

func NewToken(options *TokenOptions, signingFunc SigningFunc) (*Token, error) {
  t := &Token{
    Header: TokenHeader{
      Algorithm: options.Algorithm,
      Type:      options.Type,
      KeyId:     options.KeyId,
    },
    Payload: TokenPayload{
      Issuer:          options.Issuer,
      Audience:        options.Audience,
      AuthorizedParty: options.AuthorizedParty,
      Subject:         options.Subject,
      IssuedAt:        options.IssuedAt,
      ExpiresAt:       options.ExpiresAt,
      NotBefore:       options.NotBefore,

      claims: options.Claims,
    },
  }

  t.sign(signingFunc)
  return t, nil
}

func ParseToken(t string) (*Token, error) {
  elements := strings.SplitN(t, ".", 3)
  if len(elements) < 3 {
    return nil, errors.New("malformed token: must consist of exactly three elements")
  }

  headerBytes, err := baseDecode(elements[0])
  if err != nil {
    return nil, errwrap.Wrapf("failed to decode header: {{err}}", err)
  }

  payloadBytes, err := baseDecode(elements[1])
  if err != nil {
    return nil, errwrap.Wrapf("failed to decode payload: {{err}}", err)
  }

  signature, err := baseDecode(elements[2])
  if err != nil {
    return nil, errwrap.Wrapf("failed to decode signature: {{err}}", err)
  }

  var header TokenHeader
  err = json.Unmarshal(headerBytes, &header)
  if err != nil {
    return nil, errwrap.Wrapf("failed to decode header: {{err}}", err)
  }

  var payload TokenPayload
  err = json.Unmarshal(payloadBytes, &payload)
  if err != nil {
    return nil, errwrap.Wrapf("failed to decode payload: {{err}}", err)
  }

  return &Token{
    headerBytes,
    header,
    payloadBytes,
    payload,
    signature,
  }, nil
}

func (t *Token) sign(signingFunc SigningFunc) error {
  var err error
  t.headerBytes, err = json.Marshal(t.Header)
  if err != nil {
    return errwrap.Wrapf("failed to encode header: {{err}}", err)
  }

  t.payloadBytes, err = json.Marshal(t.Payload)
  if err != nil {
    return errwrap.Wrapf("failed to encode payload: {{err}}", err)
  }

  var msg []byte
  msg = append(msg, baseEncode(t.headerBytes)...)
  msg = append(msg, '.')
  msg = append(msg, baseEncode(t.payloadBytes)...)

  t.signature, err = signingFunc(msg)
  if err != nil {
    return errwrap.Wrapf("failed to sign token: {{err}}", err)
  }
  return nil
}

func (t *Token) Verify(verifyFunc VerifyFunc) error {
  var msg []byte
  msg = append(msg, baseEncode(t.headerBytes)...)
  msg = append(msg, '.')
  msg = append(msg, baseEncode(t.payloadBytes)...)

  return verifyFunc(msg, t.signature)
}

func (t *Token) String() (string, error) {
  return baseEncode(t.headerBytes) + "." + baseEncode(t.payloadBytes) + "." + baseEncode(t.signature), nil
}
