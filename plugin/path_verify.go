/*
 * Copyright 2018 Johannes Donath <johannesd@torchmind.com>
 * and other copyright owners as documented in the project's IP log.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jwt

import (
  "context"
  "crypto/rsa"
  "encoding/asn1"
  "fmt"
  "github.com/dotStart/vault-jwt-plugin/jwt"
  "github.com/hashicorp/errwrap"
  "github.com/hashicorp/vault/logical"
  "github.com/hashicorp/vault/logical/framework"
  "net/http"
  "strconv"
)

// provides an endpoint which permits the validation of arbitrary JWTs
func (b *jwtBackend) verifyPath() *framework.Path {
  return &framework.Path{
    Pattern:      "verify/" + framework.GenericNameRegex("name"),
    HelpSynopsis: "Permits the validation of JWTs with arbitrary contents",
    HelpDescription: `

Provides a method for the validation of previously signed JWT tokens.

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
      "token": {
        Type:        framework.TypeString,
        Description: "Token",
      },
    },
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.UpdateOperation: b.verify,
    },
  }
}

// verifies an arbitrary JWT against its respective key version
func (b *jwtBackend) verify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)
  key, err := b.getKey(ctx, req, keyName)
  if err != nil {
    return nil, err
  }
  if key == nil {
    return logical.ErrorResponse("no such key"), nil
  }

  var token *jwt.Token
  if raw, ok := d.GetOk("token"); ok {
    b.logger.Debug("verifying token", "key", keyName, "token", raw.(string))
    token, err = jwt.ParseToken(raw.(string))
    if err != nil {
      return nil, err
    }
  } else {
    return logical.ErrorResponse("token must be set"), nil
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

  if issuer != "" && token.Payload.Issuer != issuer {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "issuer mismatch",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  if audience != "" && token.Payload.Audience != audience {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "audience mismatch",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  if authorizedParty != "" && token.Payload.AuthorizedParty != authorizedParty {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "authorized party mismatch",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  if raw, ok := d.GetOk("subject"); ok {
    subject := raw.(string)

    if subject != "" && token.Payload.Subject != subject {
      response := logical.Response{
        Data: map[string]interface{}{
          "valid":  false,
          "reason": "subject mismatch",
        },
      }
      return logical.RespondWithStatusCode(&response, req, http.StatusOK)
    }
  }

  if token.Header.KeyId == "" {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "missing keyId",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  keyId, err := strconv.ParseUint(token.Header.KeyId, 10, 32)
  if err != nil {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": fmt.Sprintf("illegal keyId: %s", err.Error()),
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  version, ok := key.Versions[uint32(keyId)]
  if !ok {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "illegal keyId: no such key",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  var publicKey rsa.PublicKey
  _, err = asn1.Unmarshal(version.PublicKey, &publicKey)
  if err != nil {
    return nil, err
  }

  err = token.Verify(verifyFunction(&publicKey, key.HashAlgorithm, key.SignatureAlgorithm))
  if err != nil {
    response := logical.Response{
      Data: map[string]interface{}{
        "valid":  false,
        "reason": "signature mismatch",
      },
    }
    return logical.RespondWithStatusCode(&response, req, http.StatusOK)
  }

  response := logical.Response{
    Data: map[string]interface{}{
      "valid": true,
    },
  }
  return logical.RespondWithStatusCode(&response, req, http.StatusOK)
}

func verifyFunction(publicKey *rsa.PublicKey, hashAlgorithm HashAlgorithm, signatureAlgorithm SignatureAlgorithm) jwt.VerifyFunc {
  hash := hashAlgorithm.Hash()
  verify := signatureAlgorithm.VerifyFunc()

  return func(msg []byte, sig []byte) error {
    hh := hash.New()
    if _, err := hh.Write(msg); err != nil {
      return errwrap.Wrapf("failed to hash message: {{err}}", err)
    }

    err := verify(publicKey, hash, hh.Sum(nil), sig)
    if err != nil {
      return errwrap.Wrapf("failed to verify signature: {{err}}", err)
    }
    return nil
  }
}
