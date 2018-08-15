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
  "encoding/json"
  "errors"
  "time"
)

type TokenPayload struct {
  Issuer          string
  Audience        string
  AuthorizedParty string
  Subject         string
  IssuedAt        time.Time
  ExpiresAt       time.Time
  NotBefore       time.Time
  claims          map[string]interface{}
}

func (p TokenPayload) MarshalJSON() ([]byte, error) {
  c := make(map[string]interface{})
  if p.Issuer != "" {
    c["iss"] = p.Issuer
  }
  if p.Audience != "" {
    c["aud"] = p.Audience
  }
  if p.AuthorizedParty != "" {
    c["azp"] = p.AuthorizedParty
  }
  if p.Subject != "" {
    c["sub"] = p.Subject
  }
  if p.IssuedAt.Unix() != 0 {
    c["iat"] = p.IssuedAt.Unix()
  }
  if p.IssuedAt.Unix() != 0 {
    c["exp"] = p.ExpiresAt.Unix()
  }
  if p.IssuedAt.Unix() != 0 {
    c["nbf"] = p.NotBefore.Unix()
  }

  for key, val := range p.claims {
    c[key] = val
  }

  return json.Marshal(c)
}

func (p *TokenPayload) UnmarshalJSON(data []byte) error {
  var c map[string]interface{}
  err := json.Unmarshal(data, &c)
  if err != nil {
    return err
  }

  if raw, ok := c["iss"]; ok {
    p.Issuer, ok = raw.(string)
    if !ok {
      return errors.New("malformed issuer: not a string")
    }
  }
  if raw, ok := c["aud"]; ok {
    p.Audience, ok = raw.(string)
    if !ok {
      return errors.New("malformed audience: not a string")
    }
  }
  if raw, ok := c["azp"]; ok {
    p.AuthorizedParty, ok = raw.(string)
    if !ok {
      return errors.New("malformed authorized party: not a string")
    }
  }
  if raw, ok := c["sub"]; ok {
    p.Subject, ok = raw.(string)
    if !ok {
      return errors.New("malformed subject: not a string")
    }
  }
  if raw, ok := c["iat"]; ok {
    epoch, ok := raw.(float64)
    if !ok {
      return errors.New("malformed issuance timestamp: not an integer")
    }
    p.IssuedAt = time.Unix(int64(epoch), 0)
  }
  if raw, ok := c["exp"]; ok {
    epoch, ok := raw.(float64)
    if !ok {
      return errors.New("malformed expiration timestamp: not an integer")
    }
    p.ExpiresAt = time.Unix(int64(epoch), 0)
  }
  if raw, ok := c["nbf"]; ok {
    epoch, ok := raw.(float64)
    if !ok {
      return errors.New("malformed not before timestamp: not an integer")
    }
    p.NotBefore = time.Unix(int64(epoch), 0)
  }
  return nil
}
