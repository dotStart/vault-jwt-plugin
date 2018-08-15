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
