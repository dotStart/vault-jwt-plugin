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
