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
  "github.com/golang/protobuf/proto"
  "github.com/golang/protobuf/ptypes"
  "github.com/hashicorp/vault/helper/locksutil"
  "github.com/hashicorp/vault/logical"
  "github.com/hashicorp/vault/logical/framework"
  "net/http"
  "time"
)

// provides an endpoint configuration which permits the creation, re-configuration and deletion of
// JWT keys
func (b *jwtBackend) keysPath() *framework.Path {
  return &framework.Path{
    Pattern:      "keys/" + framework.GenericNameRegex("name"),
    HelpSynopsis: "Permits the creation, change and deletion of JWT signing configurations",
    HelpDescription: `

Provides management capabilities over globally available JWT signing keys and their respective
default claims (if desired).

`,
    Fields: map[string]*framework.FieldSchema{
      "name": {
        Type:        framework.TypeString,
        Description: "Signing key identifier",
      },
      "issuer": {
        Type:        framework.TypeString,
        Description: "Token issuer name or uri",
        Default:     "",
      },
      "audience": {
        Type:        framework.TypeString,
        Description: "Token audience (e.g. receiver) name or uri",
        Default:     "",
      },
      "authorized_party": {
        Type:        framework.TypeString,
        Description: "Token receiver name or uri",
        Default:     "",
      },
      "ttl": {
        Type:        framework.TypeDurationSecond,
        Description: "Token time to live (in seconds)",
        Default:     30 * 24 * 3600,
      },
      "claims": {
        Type:        framework.TypeKVPairs,
        Description: "Additional custom token claims",
      },
      "key_size": {
        Type:        framework.TypeInt,
        Description: "Key strength (in powers of two: 1024, 2048, 4096, 8192, 16384, ...; this value cannot be decreased once the key has been created)",
        Default:     4096,
      },
      "hash_algorithm": {
        Type:        framework.TypeString,
        Description: "Backing hashing algorithm (supported: sha-256, sha-384, sha-512)",
        Default:     "sha-256",
      },
      "signature_algorithm": {
        Type:        framework.TypeString,
        Description: "Backing signature algorithm (supported: pkcs, pss)",
        Default:     "pkcs",
      },
      "max_versions": {
        Type:        framework.TypeInt,
        Description: "Specifies the total amount of public keys to keep",
        Default:     10,
      },
      "deletable": {
        Type:        framework.TypeBool,
        Description: "Indicates whether this key may be deleted (prevents accidental deletion)",
        Default:     false,
      },
      "exportable": {
        Type:        framework.TypeBool,
        Description: "Indicates whether this private key may be exported (this value may not be changed once the key has been created)",
        Default:     false,
      },
    },
    ExistenceCheck: b.checkKeyExistence,
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.ReadOperation:   b.readKeyConfig,
      logical.CreateOperation: b.createKeyConfig,
      logical.UpdateOperation: b.updateKeyConfig,
      logical.DeleteOperation: b.deleteKeyConfig,
    },
  }
}

// provides an endpoint configuration which exposes a listing of all configured keys
func (b *jwtBackend) listKeysPath() *framework.Path {
  return &framework.Path{
    Pattern:      "keys/$",
    HelpSynopsis: "Provides a complete list of configured keys",
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.ListOperation: b.listKeyConfig,
    },
  }
}

// evaluates whether a given key has been generated and stored
// this method is used by Vault in order to decide whether create or update should be called
func (b *jwtBackend) checkKeyExistence(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
  keyName := d.Get("name").(string)

  lock := locksutil.LockForKey(b.locks, keyName)
  lock.RLock()
  defer lock.RUnlock()

  entry, err := req.Storage.Get(ctx, keyName)
  if err != nil {
    return false, err
  }
  return entry != nil, nil
}

// displays a list of existing key configurations
func (b *jwtBackend) listKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  entries, err := req.Storage.List(ctx, "")
  if err != nil {
    return nil, err
  }

  return logical.ListResponse(entries), nil
}

// retrieves an existing key configuration
func (b *jwtBackend) readKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)

  lock := locksutil.LockForKey(b.locks, keyName)
  lock.RLock()
  defer lock.RUnlock()

  entry, err := req.Storage.Get(ctx, keyName)
  if err != nil {
    return nil, err
  }
  if entry == nil {
    return logical.ErrorResponse("no such key"), nil
  }

  var key Key
  err = proto.Unmarshal(entry.Value, &key)
  if err != nil {
    return nil, err
  }

  response := &logical.Response{
    Data: encodeKey(&key),
  }
  return logical.RespondWithStatusCode(response, req, http.StatusOK)
}

// generates a new key and stores its configuration
func (b *jwtBackend) createKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)

  lock := locksutil.LockForKey(b.locks, keyName)
  lock.Lock()
  defer lock.Unlock()

  entry, err := req.Storage.Get(ctx, keyName)
  if err != nil {
    return nil, err
  }
  if entry != nil {
    return logical.ErrorResponse("key already exists"), nil
  }

  var issuer string
  if raw, ok := d.GetOk("issuer"); ok {
    issuer = raw.(string)
  } else {
    return logical.ErrorResponse("issuer must be set"), nil
  }

  keySize := d.Get("key_size").(int)
  if keySize == 0 || (keySize&(keySize-1)) != 0 {
    return logical.ErrorResponse("key_size must be a power of two"), nil
  }

  hashAlgorithm := parseHashAlgorithm(d.Get("hash_algorithm").(string))
  if hashAlgorithm == -1 {
    return logical.ErrorResponse("unsupported hash_algorithm"), nil
  }

  signatureAlgorithm := parseSignatureAlgorithm(d.Get("signature_algorithm").(string))
  if signatureAlgorithm == -1 {
    return logical.ErrorResponse("unsupported signature_algorithm"), nil
  }

  audience := d.Get("audience").(string)
  authorizedParty := d.Get("authorized_party").(string)
  ttl := d.Get("ttl").(int)
  maxVersions := d.Get("max_versions").(int)
  deletable := d.Get("deletable").(bool)
  exportable := d.Get("exportable").(bool)

  creationTimestamp := time.Now()
  creationTimestampProto, _ := ptypes.TimestampProto(creationTimestamp)

  if maxVersions <= 0 {
    return logical.ErrorResponse("max_version must be at least one"), nil
  }

  b.logger.Info("generating new key", "key", keyName, "strength", keySize)

  ver, err := b.generateKeyVersion(keySize)
  if err != nil {
    return nil, err
  }

  key := Key{
    Name:           keyName,
    CurrentVersion: 1,
    Versions: map[uint32]*Version{
      1: ver,
    },
    Issuer:             issuer,
    Audience:           audience,
    AuthorizedParty:    authorizedParty,
    Ttl:                ptypes.DurationProto(time.Second * time.Duration(ttl)),
    Claims:             d.Get("claims").(map[string]string),
    KeySize:            uint32(keySize),
    HashAlgorithm:      hashAlgorithm,
    SignatureAlgorithm: signatureAlgorithm,
    MaxVersions:        uint32(maxVersions),
    Deletable:          deletable,
    Exportable:         exportable,
    CreatedAt:          creationTimestampProto,
    UpdatedAt:          creationTimestampProto,
  }

  b.logger.Debug(
    "storing new key",

    "key", keyName,
    "issuer", issuer,
    "audience", audience,
    "authorized_party", authorizedParty,
    "ttl", (time.Second * time.Duration(ttl)).String(),
    "strength", keySize,
    "hash_algorithm", hashAlgorithm.String(),
    "signature_algorithm", signatureAlgorithm.String(),
    "max_versions", maxVersions,
    "deletable", deletable,
    "exportable", exportable,
    "created_at", creationTimestamp,
    "updated_at", creationTimestamp,
  )
  b.writeKey(ctx, req, keyName, &key)

  response := &logical.Response{
    Data: encodeKey(&key),
  }
  return logical.RespondWithStatusCode(response, req, http.StatusOK)
}

// updates the key configuration
func (b *jwtBackend) updateKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)

  lock := locksutil.LockForKey(b.locks, keyName)
  lock.Lock()
  defer lock.Unlock()

  key, err := b.readKey(ctx, req, keyName)
  if err != nil {
    return nil, err
  }
  if key == nil {
    return logical.ErrorResponse("no such key"), nil
  }

  warnings := make([]string, 0)
  if raw, ok := d.GetOk("issuer"); ok {
    val := raw.(string)
    if val != "" {
      key.Issuer = raw.(string)
    } else {
      warnings = append(warnings, "issuer must be set")
    }
  }
  if raw, ok := d.GetOk("audience"); ok {
    key.Audience = raw.(string)
  }
  if raw, ok := d.GetOk("authorized_party"); ok {
    key.AuthorizedParty = raw.(string)
  }
  if raw, ok := d.GetOk("ttl"); ok {
    key.Ttl = ptypes.DurationProto(time.Second * time.Duration(raw.(int)))
  }
  if raw, ok := d.GetOk("claims"); ok {
    key.Claims = raw.(map[string]string)
  }
  if raw, ok := d.GetOk("max_versions"); ok {
    val := raw.(int)
    if val > 1 {
      key.MaxVersions = uint32(val)
    } else {
      warnings = append(warnings, "max_versions must be set to at least one")
    }
  }
  if raw, ok := d.GetOk("deletable"); ok {
    key.Deletable = raw.(bool)
  }
  b.writeKey(ctx, req, keyName, key)

  response := &logical.Response{
    Data:     encodeKey(key),
    Warnings: warnings,
  }
  return logical.RespondWithStatusCode(response, req, http.StatusOK)
}

// deletes a key configuration
func (b *jwtBackend) deleteKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  keyName := d.Get("name").(string)

  key, err := b.getKey(ctx, req, keyName)
  if err != nil {
    b.logger.Warn("cannot read key - deletion lock check skipped", "key", keyName, "err", err.Error())
  } else if !key.Deletable {
    return logical.ErrorResponse("key is protected"), nil
  }

  return nil, req.Storage.Delete(ctx, keyName)
}
