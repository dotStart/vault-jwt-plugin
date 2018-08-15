package jwt

import (
  "context"
  "crypto/rsa"
  "crypto/x509"
  "errors"
  "fmt"
  "github.com/dotStart/vault-jwt-plugin/jwt"
  "github.com/golang/protobuf/ptypes"
  "github.com/hashicorp/errwrap"
  "github.com/hashicorp/vault/logical"
  "github.com/hashicorp/vault/logical/framework"
  "net/http"
  "time"
)

// provides an endpoint configuration which permits the signing of arbitrary JWT claims
func (b *jwtBackend) signPath() *framework.Path {
  return &framework.Path{
    Pattern:      "sign/" + framework.GenericNameRegex("name"),
    HelpSynopsis: "Permits the creation of new JWTs with arbitrary contents",
    HelpDescription: `

Provides a method to create JWTs with arbitrary contents. When no value is provided for a given
claim, the token's configured claims will be substituted.

`,
    Fields: map[string]*framework.FieldSchema{
      "name": {
        Type:        framework.TypeString,
        Description: "Signing key identifier",
      },
      "issuer": {
        Type:        framework.TypeString,
        Description: "Token issuer name or uri",
      },
      "audience": {
        Type:        framework.TypeString,
        Description: "Token audience (e.g. receiver) name or uri",
      },
      "authorized_party": {
        Type:        framework.TypeString,
        Description: "Token receiver name or uri",
      },
      "subject": {
        Type:        framework.TypeString,
        Description: "Token subject",
      },
      "ttl": {
        Type:        framework.TypeDurationSecond,
        Description: "Token time to live (in seconds)",
      },
      "claims": {
        Type:        framework.TypeKVPairs,
        Description: "Additional custom token claims",
      },
      "not_before": {
        Type:        framework.TypeString,
        Description: "Specifies the time from which the token shall be considered valid",
      },
    },
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.UpdateOperation: b.sign,
    },
  }
}

// signs arbitrary JWT claims using the current key revision
func (b *jwtBackend) sign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)
  key, err := b.getKey(ctx, req, keyName)
  if err != nil {
    return nil, err
  }
  if key == nil {
    return logical.ErrorResponse("no such key"), nil
  }

  keyId := key.CurrentVersion
  ver, ok := key.Versions[keyId]
  if !ok {
    return nil, errors.New("malformed key: encoded key does not contain specification for current key version")
  }

  privateKey, err := x509.ParsePKCS8PrivateKey(ver.PrivateKey)
  if err != nil {
    return nil, err
  }

  var subject string
  if raw, ok := d.GetOk("subject"); ok {
    subject = raw.(string)
  } else {
    return logical.ErrorResponse("subject must be specified"), nil
  }

  var issuer string
  if raw, ok := d.GetOk("issuer"); ok {
    issuer = raw.(string)
  } else {
    issuer = key.Issuer
  }

  var audience string
  if raw, ok := d.GetOk("audience"); ok {
    audience = raw.(string)
  } else {
    audience = key.Audience
  }

  var authorizedParty string
  if raw, ok := d.GetOk("authorized_party"); ok {
    authorizedParty = raw.(string)
  } else {
    authorizedParty = key.AuthorizedParty
  }

  now := time.Now()
  var nbf time.Time
  if raw, ok := d.GetOk("not_before"); ok {
    nbf, err = time.Parse(time.RFC3339, raw.(string))
  } else {
    nbf = now
  }

  var ttl time.Duration
  if raw, ok := d.GetOk("ttl"); ok {
    ttl = time.Second * time.Duration(raw.(int))
  } else {
    val, _ := ptypes.Duration(key.Ttl)
    ttl = val
  }

  exp := nbf.Add(ttl)

  opts := &jwt.TokenOptions{
    Algorithm: key.TokenAlgorithm(),
    Type:      "JWT",
    KeyId:     fmt.Sprintf("%d", key.CurrentVersion),

    Issuer:          issuer,
    Audience:        audience,
    AuthorizedParty: authorizedParty,
    Subject:         subject,

    IssuedAt:  now,
    NotBefore: nbf,
    ExpiresAt: exp,
  }
  t, err := jwt.NewToken(opts, signFunction(privateKey.(*rsa.PrivateKey), key.HashAlgorithm, key.SignatureAlgorithm))

  enc, err := t.String()
  if err != nil {
    return nil, err
  }

  b.logger.Debug("signed token", "key", keyName, "issuer", issuer, "audience", audience, "authorized_party", authorizedParty, "subject", subject, "issued_at", now, "not_before", nbf, "expires_at", exp)

  response := &logical.Response{
    Data: map[string]interface{}{
      "token": enc,
    },
  }
  return logical.RespondWithStatusCode(response, req, http.StatusOK)
}

func signFunction(privateKey *rsa.PrivateKey, hashAlgorithm HashAlgorithm, signatureAlgorithm SignatureAlgorithm) jwt.SigningFunc {
  hash := hashAlgorithm.Hash()
  sign := signatureAlgorithm.SignFunc()

  return func(msg []byte) ([]byte, error) {
    hh := hash.New()
    if _, err := hh.Write(msg); err != nil {
      return nil, errwrap.Wrapf("failed to hash message: {{err}}", err)
    }

    sig, err := sign(privateKey, hash, hh.Sum(nil))
    if err != nil {
      return nil, errwrap.Wrapf("failed to generate signature: {{err}}", err)
    }
    return sig, nil
  }
}
