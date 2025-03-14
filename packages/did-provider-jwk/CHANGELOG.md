# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.28.0](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/compare/v0.27.0...v0.28.0) (2025-03-14)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.27.0](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/compare/v0.26.0...v0.27.0) (2024-12-05)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.26.0](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/compare/v0.25.0...v0.26.0) (2024-11-26)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.25.0](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/compare/v0.24.0...v0.25.0) (2024-10-28)

### Features

- Add JWS signature verification; Add cose key conversions and resolution (managed and external) ([9f76393](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/commit/9f7639322d825bd7ec0a276adfb6ab4a934fc571))
- External resolution of keys and validations for DIDs and x5c ([01db327](https://github.com/Sphereon-OpenSource/SSI-SDK-crypto-extensions/commit/01db32715f7e7a95b57e07c23b7f3cc5b6ffa578))

# [0.24.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.23.0...v0.24.0) (2024-08-01)

### Bug Fixes

- Fix key usages for jwks when importing keys ([c473572](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/c473572dc14105fec4626f596b21aebf180079da))

### Features

- Improve kid determination. Rename most `kid` arguments to kmsKeyRef, as these are only the internal KMS kids. Preventing confusion. Improve did functions to accept object args. ([22f465c](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/22f465c9b7bfc5b5f628557c6a0631ae5817d444))

# [0.23.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.22.0...v0.23.0) (2024-07-23)

### Features

- Make key/vm from identifier/did functions more future proof and add option to search for controller keys and key types ([f691789](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/f6917899680c1f39a98a0afbf181e821edadd4a3))

# [0.22.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.21.0...v0.22.0) (2024-07-02)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.21.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.20.0...v0.21.0) (2024-06-19)

### Bug Fixes

- Multiple DID EBSI fixes ([131faa0](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/131faa0b583063cb3d8d5e77a33f337a23b90536))

# [0.20.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.19.0...v0.20.0) (2024-06-13)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.19.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.18.2...v0.19.0) (2024-04-25)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

## [0.18.2](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.18.1...v0.18.2) (2024-04-24)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

## [0.18.1](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.18.0...v0.18.1) (2024-04-04)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.18.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.17.0...v0.18.0) (2024-03-19)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.17.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.16.0...v0.17.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-jwk

# [0.16.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.15.0...v0.16.0) (2024-01-13)

### Bug Fixes

- did:key ebsi / jcs codec value was wrong ([a71279e](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/a71279e3b79bff4add9fa4c889459264419accc6))

# [0.15.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.14.1...v0.15.0) (2023-09-30)

### Features

- check whether resolution is configured properly ([01a693b](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/01a693b94cd612826312168973caf15b0441ebf0))

## [0.14.1](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.14.0...v0.14.1) (2023-09-28)

### Bug Fixes

- public key mapping updates, fixing ed25519 with multibase encoding ([489d4f2](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/489d4f20e0f354eb50b1a16a91472d4e85588113))

# [0.14.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.13.0...v0.14.0) (2023-08-09)

### Bug Fixes

- RSA import fixes ([77704a2](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/77704a2064e1c1d3ffc23e580ddbb36063fc70ae))

# [0.13.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.12.1...v0.13.0) (2023-07-30)

### Features

- Add agent resolver method ([3c7b21e](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))

## [0.12.1](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.12.0...v0.12.1) (2023-06-24)

### Bug Fixes

- Fix EC handling for JWKs ([7be20f5](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/7be20f57d6b7d4b7ebf5a2e9b432da34f8f98436))
- Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
- Make sure we set the saltLength for RSA PSS ([51ae676](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/51ae6769386866771c68c7b7806a75b62a9d5ec1))
- Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))

# [0.12.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.11.0...v0.12.0) (2023-05-07)

### Features

- Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))

# [0.11.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.10.2...v0.11.0) (2023-04-30)

### Features

- Add EBSI LE DID Provider (does not persist into the registry yet) ([7a8cf56](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/7a8cf5687152ba0a7449d93eeb40289d6af07acf))
- add key utils package for common key functions ([0543254](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/0543254d14b4ba54adeeab944315db5ba6221d47))
- Move to pnpm from yarn ([6ed9bd5](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/6ed9bd5fe72645364e631be1628710f57d5deb19))
- Reorganize SSI-SDK crypto extensions and DIDs ([5578914](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/55789146f48b31e8efdd64afa464a42779a2137b))

# [0.9.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.8.0...v0.9.0) (2023-03-09)

### Features

- add Alg support to DID:JWK. Although optional in reality several external systems expect it to be present ([12dae72](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/12dae72860fd0dc00e96a8121b136c2195843388))
- Add support for ES256/Secp256r1 DID JWKs ([1e447a6](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/1e447a6fedab92549d8848a13212e9dd8c75274a))
- Allow to relax JWT timing checks, where the JWT claim is slightly different from the VC claim. Used for issuance and expiration dates ([85bff6d](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/85bff6da21dea5d8f636ea1f55b41be00b18b002))

# Change Log
