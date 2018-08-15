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
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/asn1"
  "encoding/json"
  "encoding/pem"
  "github.com/golang/protobuf/proto"
  "github.com/golang/protobuf/ptypes/timestamp"
  "github.com/hashicorp/vault/helper/locksutil"
  "github.com/hashicorp/vault/logical"
  "time"
)

// retrieves a key representation from Vault's secure storage
// this method assumes that the caller has already acquired a read or write lock for the respective
// key
func (b *jwtBackend) readKey(ctx context.Context, req *logical.Request, keyName string) (*Key, error) {
  entry, err := req.Storage.Get(ctx, keyName)
  if err != nil {
    return nil, err
  }
  if entry == nil {
    return nil, nil
  }

  var key Key
  err = proto.Unmarshal(entry.Value, &key)
  return &key, err
}

// retrieves a key representation from Vault's secure storage
func (b *jwtBackend) getKey(ctx context.Context, req *logical.Request, keyName string) (*Key, error) {
  lock := locksutil.LockForKey(b.locks, keyName)
  lock.RLock()
  defer lock.RUnlock()

  return b.readKey(ctx, req, keyName)
}

// serializes a key back into Vault's secure storage
func (b *jwtBackend) writeKey(ctx context.Context, req *logical.Request, keyName string, key *Key) error {
  enc, err := proto.Marshal(key)
  if err != nil {
    return err
  }

  err = req.Storage.Put(ctx, &logical.StorageEntry{
    Key:   keyName,
    Value: enc,
  })
  if err != nil {
    return err
  }
  return nil
}

// generates a new key version using the indicated key strength
func (b *jwtBackend) generateKeyVersion(keySize int) (*Version, error) {
  reader := rand.Reader
  privateKey, err := rsa.GenerateKey(reader, keySize)
  if err != nil {
    return nil, err
  }

  encKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
  if err != nil {
    return nil, err
  }

  encPublicKey, err := asn1.Marshal(privateKey.PublicKey)
  if err != nil {
    return nil, err
  }

  return &Version{
    PublicKey:  encPublicKey,
    PrivateKey: encKey,
    CreatedAt:  &timestamp.Timestamp{Seconds: time.Now().Unix()},
  }, nil
}

// converts a human readable string into its respective hash algorithm constant
func parseHashAlgorithm(algorithm string) HashAlgorithm {
  switch algorithm {
  case "sha-256":
    return HashAlgorithm_sha256
  case "sha-384":
    return HashAlgorithm_sha384
  case "sha-512":
    return HashAlgorithm_sha512
  default:
    return -1
  }
}

// converts a human readable string into its respective signature algorithm constant
func parseSignatureAlgorithm(algorithm string) SignatureAlgorithm {
  switch algorithm {
  case "pkcs":
    return SignatureAlgorithm_pkcs
  case "pss":
    return SignatureAlgorithm_pss
  default:
    return -1
  }
}

// encodes a public key into its sharable PEM format
func encodePublicKey(key []byte) string {
  blk := &pem.Block{
    Type:  "PUBLIC KEY",
    Bytes: key,
  }

  return string(pem.EncodeToMemory(blk))
}

// encodes a key into a transmittable format
func encodeKey(key *Key) map[string]interface{} {
  versions := make(map[uint32]map[string]interface{}, 0)
  for i, version := range key.Versions {
    versions[i] = map[string]interface{}{
      "public_key": encodePublicKey(version.PublicKey),
      "created_at": time.Unix(version.CreatedAt.Seconds, int64(version.CreatedAt.Nanos)),
    }

    if version.DeletedAt != nil {
      versions[i]["deleted_at"] = time.Unix(version.DeletedAt.Seconds, int64(version.DeletedAt.Nanos))
    }
  }

  // TODO: Error handling?
  verEnc, _ := json.Marshal(versions)
  claimEnc, _ := json.Marshal(key.Claims)

  return map[string]interface{}{
    "name":                key.Name,
    "current_version":     key.CurrentVersion,
    "versions":            string(verEnc),
    "issuer":              key.Issuer,
    "audience":            key.Audience,
    "authorized_party":    key.AuthorizedParty,
    "ttl":                 key.Ttl.Seconds,
    "claims":              string(claimEnc),
    "key_size":            key.KeySize,
    "hash_algorithm":      key.HashAlgorithm.String(),
    "signature_algorithm": key.SignatureAlgorithm.String(),
    "max_versions":        key.MaxVersions,
    "exportable":          key.Exportable,
    "deletable":           key.Deletable,
    "created_at":          time.Unix(key.CreatedAt.Seconds, int64(key.CreatedAt.Nanos)),
    "updated_at":          time.Unix(key.UpdatedAt.Seconds, int64(key.UpdatedAt.Nanos)),
  }
}

// retrieves a string representation for the chosen signature algorithm
func (k *Key) TokenAlgorithm() string {
  var prefix string
  if k.SignatureAlgorithm == SignatureAlgorithm_pss {
    prefix = "PS"
  } else {
    prefix = "RS"
  }

  var suffix string
  switch k.HashAlgorithm {
  case HashAlgorithm_sha256:
    suffix = "256"
  case HashAlgorithm_sha384:
    suffix = "384"
  case HashAlgorithm_sha512:
    suffix = "512"
  }

  return prefix + suffix
}

var hashAlgorithms = []crypto.Hash{
  crypto.SHA256,
  crypto.SHA384,
  crypto.SHA512,
}

func (h *HashAlgorithm) Hash() crypto.Hash {
  return hashAlgorithms[int(*h)]
}

var signatureFunctions = []func(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error){
  func(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
    return rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed)
  },
  func(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
    return rsa.SignPSS(rand.Reader, priv, hash, hashed, &rsa.PSSOptions{
      SaltLength: rsa.PSSSaltLengthAuto,
    })
  },
}

func (s *SignatureAlgorithm) SignFunc() func(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
  return signatureFunctions[int(*s)]
}

var verifyFunctions = []func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error{
  rsa.VerifyPKCS1v15,
  func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
    return rsa.VerifyPSS(pub, hash, hashed, sig, &rsa.PSSOptions{
      SaltLength: rsa.PSSSaltLengthAuto,
    })
  },
}

func (s *SignatureAlgorithm) VerifyFunc() func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
  return verifyFunctions[int(*s)]
}
