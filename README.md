<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
  <br>Sphereon SSI SDK Crypto Extensions 
  <br>
</h1>

---

# BBS+, RSA, JWK, EBSI DID and key management support

This mono repository, contains packages that add different crypto keys and signature suites as well as different DID
methods to the [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk). The packages are also compatible
with [Veramo](https://veramo.io).

## Key Management

| Plugin                                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Key Manager](./packages/key-manager)               | The Key Manager orchestrates the various implementations of Key Management Systems, using a KeyStore to remember the link between a key reference, its metadata, and the respective key management system that provides the actual cryptographic capabilities. The methods of this plugin are used automatically by other plugins, such as DIDManager, CredentialPlugin, or DIDComm to perform their required cryptographic operations using the managed keys. You will need this version if you want to use BLS/BBS+ keys |
| [Local Key Management System](./packages/kms-local) | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible Key Management System that stores keys in a local key store. It has support for RSA, BLS/BBS+ signatures, next to ed25519, es256k1, es256r1                                                                                                                                                                                                                                                                          |
| [Key Utils](./packages/key-utils)                   | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible Key Utility and generation functions                                                                                                                                                                                                                                                                                                                                                                                 |
| [DID Utils](./packages/did-utils)                   | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible DID functions                                                                                                                                                                                                                                                                                                                                                                                                        |

## DID Methods

The below packages can be used both in our [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk)
and [Veramo](https://veramo.io/). The below packages extend did:key and support did:jwk.

| DID methods                                           | Description                                                                                                                                                                                                                                                                                                |
|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [DIF did:key resolver](./packages/did-resolver-key)   | [DIF DID resolver](https://github.com/decentralized-identity/did-resolver) compatible [did:key](https://w3c-ccg.github.io/did-method-key/) resolver with support for BLS/BBS+, JWK (EBSI natural persons), ed25519, es256k1, es256r1, es384r1, es521r1.                                                    |
| [did:key provider](./packages/did-provider-key)       | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible [did:key](https://w3c-ccg.github.io/did-method-key/) provider, allows you to manage keys and DIDs with support for BLS/BBS+, JWK (EBSI natural persons), ed25519, es256k1, es256r1, es384r1, es521r1 |
| [DIF did:jwk resolver](./packages/did-resolver-key)   | [DIF DID resolver](https://github.com/decentralized-identity/did-resolver) compatible [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md) resolver with support for ed25519, es256k1, es256r1, RSA keys.                                                                                     |
| [did:jwk provider](./packages/did-provider-jwk)       | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible [did:jwk](https://w3c-ccg.github.io/did-method-key/) provider, allows you to manage JWK keys and DIDs                                                                                                |
| [DIF did:ebsi resolver](./packages/did-resolver-ebsi) | [DIF DID resolver](https://github.com/decentralized-identity/did-resolver) compatible [did:ebsi](https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method) v1 Legal Entity resolver                                                                                              |
| [did:ebsi provider](./packages/did-provider-ebsi)     | [SSI-SDK](https://github.com/Sphereon-Opensource/ssi-sdk) and [Veramo](https://veramo.io/) compatible [did:ebsi](https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method) v1 Legal Entity provider, allows you to manage ebsi v1 keys and DIDs                                  |

## Building and testing

### Lerna

This package makes use of Lerna for managing multiple packages. Lerna is a tool that optimizes the workflow around
managing multi-package repositories with git and npm / pnpm.

### Build

The below command builds all packages for you

```shell
pnpm build
```

### Test

The test command runs:

* `jest`
* `coverage`

You can also run only a single section of these tests, using for example `pnpm test:watch`.

```shell
pnpm test
```

### Utility scripts

There are other utility scripts that help with development.

* `pnpm prettier` - runs `prettier` to fix code style.

### Publish

There are scripts that can publish the following versions:

* `latest`
* `next`
* `unstable`

```shell
pnpm publish:[version]
```
