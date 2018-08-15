package jwt

type TokenHeader struct {
  Algorithm string `json:"alg,omitempty"`
  Type      string `json:"typ,omitempty"`
  KeyId     string `json:"keyid,omitempty"`
}
