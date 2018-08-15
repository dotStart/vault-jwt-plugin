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
  "github.com/golang/protobuf/ptypes"
  "github.com/hashicorp/vault/helper/locksutil"
  "github.com/hashicorp/vault/logical"
  "github.com/hashicorp/vault/logical/framework"
  "net/http"
  "sort"
)

// provides an endpoint configuration which permits the rotation of the backing encryption key
func (b *jwtBackend) rotatePath() *framework.Path {
  return &framework.Path{
    Pattern:      "keys/" + framework.GenericNameRegex("name") + "/rotate",
    HelpSynopsis: "Rotates a signing key",
    HelpDescription: `

Exchanges an existing private/public key pair and replaces it with a new version. This endpoint will
automatically remove old key versions and delete any prior stored private keys.

`,
    Fields: map[string]*framework.FieldSchema{
      "name": {
        Type:        framework.TypeString,
        Description: "Signing key identifier",
      },
    },
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.UpdateOperation: b.rotateKey,
    },
  }
}

// rotates the private key for a given jwt configuration
func (b *jwtBackend) rotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

  b.logger.Info("rotating key", "key", keyName, "strength", key.KeySize)

  currentVer, ok := key.Versions[key.CurrentVersion]
  if ok {
    currentVer.PrivateKey = nil
    currentVer.DeletedAt = ptypes.TimestampNow()
  } else {
    b.logger.Warn("current key version is missing from storage", "key", keyName, "version", key.CurrentVersion)
  }

  sortedVersions := make([]uint32, 0)
  for key := range key.Versions {
    sortedVersions = append(sortedVersions, key)
  }

  if len(sortedVersions) >= int(key.MaxVersions) {
    sort.Slice(sortedVersions, func(i, j int) bool {
      creationI, _ := ptypes.Timestamp(key.Versions[sortedVersions[i]].CreatedAt)
      creationJ, _ := ptypes.Timestamp(key.Versions[sortedVersions[j]].CreatedAt)

      return creationI.Before(creationJ)
    })

    remaining := (uint32(len(sortedVersions)) - key.MaxVersions) + 1
    for i := 0; i < len(sortedVersions) && remaining > 0; i++ {
      delete(key.Versions, sortedVersions[i])
      b.logger.Debug("deleted key version", "key", keyName, "version", sortedVersions[i])
      remaining--
    }
  }

  keyVersion := key.CurrentVersion + 1
  if keyVersion < key.CurrentVersion {
    b.logger.Warn("keyId has wrapped around", "key", keyName, "version", key.CurrentVersion)
  }

  ver, err := b.generateKeyVersion(int(key.KeySize))

  key.Versions[keyVersion] = ver
  key.CurrentVersion = keyVersion
  b.writeKey(ctx, req, keyName, key)

  response := &logical.Response{
    Data: encodeKey(key),
  }
  return logical.RespondWithStatusCode(response, req, http.StatusOK)
}
