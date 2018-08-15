package jwt

import (
  "encoding/base64"
)

func baseEncode(data []byte) string {
  return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}

func baseDecode(data string) ([]byte, error) {
  return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(data)
}
