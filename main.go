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
package main

import (
  "github.com/dotStart/vault-jwt-plugin/plugin"
  "github.com/hashicorp/vault/helper/pluginutil"
  "github.com/hashicorp/vault/logical/plugin"
  "log"
  "os"
)

func main() {
  apiClientMeta := &pluginutil.APIClientMeta{}
  flags := apiClientMeta.FlagSet()
  flags.Parse(os.Args[1:])

  tlsConfig := apiClientMeta.GetTLSConfig()
  tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

  err := plugin.Serve(&plugin.ServeOpts{
    BackendFactoryFunc: jwt.Factory,
    TLSProviderFunc:    tlsProviderFunc,
  })
  if err != nil {
    log.Println(err)
    os.Exit(1)
  }
}
