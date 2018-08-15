package jwt

import (
  "context"
  log "github.com/hashicorp/go-hclog"
  "github.com/hashicorp/vault/helper/locksutil"
  "github.com/hashicorp/vault/logical"
  "github.com/hashicorp/vault/logical/framework"
)

//go:generate protoc -I=proto/ --go_out=. proto/key.proto

type jwtBackend struct {
  *framework.Backend
  logger log.Logger
  locks  []*locksutil.LockEntry
}

func Factory(ctx context.Context, cfg *logical.BackendConfig) (logical.Backend, error) {
  b := newBackend(cfg)
  if err := b.Setup(ctx, cfg); err != nil {
    return nil, err
  }
  return b, nil
}

func newBackend(cfg *logical.BackendConfig) *jwtBackend {
  cfg.Logger.Info("initialized plugin instance: %v", cfg.Config)

  var b jwtBackend
  b.logger = cfg.Logger
  b.Backend = &framework.Backend{
    BackendType: logical.TypeLogical,
    Help:        backendHelp,
    Paths: []*framework.Path{
      b.listKeysPath(),
      b.keysPath(),
      b.rotatePath(),
      b.signPath(),
      b.verifyPath(),
    },
  }
  b.locks = locksutil.CreateLocks()
  return &b
}

const backendHelp = `This backend provides methods for generating and validating JWTs`
