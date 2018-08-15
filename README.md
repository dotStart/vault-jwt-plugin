Vault JWT Backend
=================

Provides a plugin backend which permits the signing and validation of JWT tokens using a securely
stored key.

Installation
------------

On production instance (e.g. when Vault is not running in development mode as described below),
you are required to manually configure the plugin within the plugin catalog. Note that the
following commands assume that you placed the executable within the configured plugin directory.

```
plugin_checksum=$(cat sha256.sig)
vault write sys/plugins/catalog/jwt-backend sha_256=${plugin_checksum} command=jwt-backend
```

In development environments, Vault will automatically load any plugins and register them with the
catalog (when the executable is changed, Vault will need to be restarted or the record must be
updated with the new checksum):

```
vault server -dev -dev-plugin-dir=/my/plugin/dir
```

The backend may be mounted via the command line using the `secrets` command:

```
vault secrets enable -plugin-name=jwt-backend -path=jwt plugin
```

Prerequisites
-------------

* go (1.10 or newer)
* dep
* protobuf (including protobuf go plugin)

Building
--------

1. `go get -d -u github.com/dotStart/vault-jwt-plugin/...`
2. `cd $(go env GOPATH)/src/github.com/dotStart/vault-jwt-plugin`
3. `make`

The resulting binaries will be located within the `build` directory along with their respective
SHA-256 checksums.

License
-------

```
Copyright [year] [name] <[email]>
and other copyright owners as documented in the project's IP log.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
