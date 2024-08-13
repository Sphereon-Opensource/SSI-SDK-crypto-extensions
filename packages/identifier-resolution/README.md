<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
  <br>Managed and external identifier resolution 
  <br>
</h1>

A plugin that in a uniform way can resolve any supported external identifiers, as well as get managed identifiers.

Currently, it supports the following identifier methods and types:

- DIDs (and the internal IIdentifier type)
- JWKs (JWK object and public key in hex)
- kid, KMS key references and jwk thumbprints
- X.509 certificate chains

TODO:

- https .well-knowns (JWKSet)
- X.509 CN en SANs

Since the plugin dynamically looks for the correct agent plugins based on the types being resolved, this plugin should
be used for any and all identifier resolution.

No matter whether the plugin is doing resolution of external identifiers or managed/internal identifiers, the results
will always include certain objects, like the JWK key(s) associated, certificates etc. This ensures uniform handling in
all places that rely on key/identifier management.

### Installation

```shell
pnpm add @sphereon/ssi-sdk-ext.identifier-resolution
```

### Build

```shell
pnpm run build
```

### Test

The test command runs:

- `prettier`
- `jest`
- `coverage`

You can also run only a single section of these tests, using for example `yarn test:unit`.

```shell
pnmp run test
```
