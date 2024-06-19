# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.21.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.20.0...v0.21.0) (2024-06-19)

### Bug Fixes

- Multiple DID EBSI fixes ([131faa0](https://github.com/Sphereon-Opensource/SSI-SDK/commit/131faa0b583063cb3d8d5e77a33f337a23b90536))

### Features

- Ensure we can actually pass in bearer tokens & misc cleanups ([4abc507](https://github.com/Sphereon-Opensource/SSI-SDK/commit/4abc507e2b0dda53cc77cb00a55d4b432e6c38de))

# [0.20.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.19.0...v0.20.0) (2024-06-13)

### Bug Fixes

- Bugfix creating eth transactions ([1d2e04d](https://github.com/Sphereon-Opensource/SSI-SDK/commit/1d2e04da8e682ffa725f280d3863fc66a4fe0f9a))
- Fixed broken tests ([07d320a](https://github.com/Sphereon-Opensource/SSI-SDK/commit/07d320a4a04bfd41093e6ed7133b81134aa6a381))

### Features

- Added secp256r1 key to createIdentifier() method ([81fff51](https://github.com/Sphereon-Opensource/SSI-SDK/commit/81fff5196b74fe3f579407a19f60cb67db554bbb))
- Implemented conversion of public keys, rpc service and documentation ([b0ac3b5](https://github.com/Sphereon-Opensource/SSI-SDK/commit/b0ac3b5d9fea4a4d37d6175057ff131ffee38307))
- Implemented integration of the ebsi rpc service with the ebsi did provider ([3c1ef0d](https://github.com/Sphereon-Opensource/SSI-SDK/commit/3c1ef0da981f86f0b8241d5fcab65d32f03584ba))

# [0.19.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.2...v0.19.0) (2024-04-25)

### Features

- Added secp256r1 key to createIdentifier() method ([f8da68d](https://github.com/Sphereon-Opensource/SSI-SDK/commit/f8da68d0b79a8977128bcfa16673ab8bf8547b58))

## [0.18.2](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.1...v0.18.2) (2024-04-24)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-ebsi

## [0.18.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.0...v0.18.1) (2024-04-04)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-ebsi

# [0.18.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.17.0...v0.18.0) (2024-03-19)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-ebsi

# [0.17.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.16.0...v0.17.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-ebsi

# [0.16.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.15.0...v0.16.0) (2024-01-13)

### Bug Fixes

- did:key ebsi / jcs codec value was wrong ([a71279e](https://github.com/Sphereon-Opensource/SSI-SDK/commit/a71279e3b79bff4add9fa4c889459264419accc6))

# [0.15.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.14.1...v0.15.0) (2023-09-30)

### Features

- check whether resolution is configured properly ([01a693b](https://github.com/Sphereon-Opensource/SSI-SDK/commit/01a693b94cd612826312168973caf15b0441ebf0))

## [0.14.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.14.0...v0.14.1) (2023-09-28)

### Bug Fixes

- public key mapping updates, fixing ed25519 with multibase encoding ([489d4f2](https://github.com/Sphereon-Opensource/SSI-SDK/commit/489d4f20e0f354eb50b1a16a91472d4e85588113))

# [0.14.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.13.0...v0.14.0) (2023-08-09)

### Bug Fixes

- RSA import fixes ([77704a2](https://github.com/Sphereon-Opensource/SSI-SDK/commit/77704a2064e1c1d3ffc23e580ddbb36063fc70ae))

# [0.13.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.12.1...v0.13.0) (2023-07-30)

### Features

- Add agent resolver method ([3c7b21e](https://github.com/Sphereon-Opensource/SSI-SDK/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))
- Add DID web provider, with RSA and multi key import support ([8335fbe](https://github.com/Sphereon-Opensource/SSI-SDK/commit/8335fbe16e4a7740a11e225c99afb516c305d27f))

## [0.12.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.12.0...v0.12.1) (2023-06-24)

### Bug Fixes

- Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-Opensource/SSI-SDK/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))

# [0.12.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.11.0...v0.12.0) (2023-05-07)

### Features

- Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-Opensource/SSI-SDK/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))

# [0.11.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.2...v0.11.0) (2023-04-30)

### Features

- Add EBSI LE DID Provider (does not persist into the registry yet) ([7a8cf56](https://github.com/Sphereon-Opensource/SSI-SDK/commit/7a8cf5687152ba0a7449d93eeb40289d6af07acf))
- add key utils package for common key functions ([0543254](https://github.com/Sphereon-Opensource/SSI-SDK/commit/0543254d14b4ba54adeeab944315db5ba6221d47))

## [0.10.2](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.1...v0.10.2) (2023-03-11)

**Note:** Version bump only for package @sphereon/bls-did-provider-key

## [0.10.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.0...v0.10.1) (2023-03-10)

**Note:** Version bump only for package @sphereon/bls-did-provider-key

# [0.10.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.9.1...v0.10.0) (2023-03-09)

### Bug Fixes

- move to maintained isomorphic-webcrypto ([#2](https://github.com/Sphereon-Opensource/SSI-SDK/issues/2)) ([b392ca5](https://github.com/Sphereon-Opensource/SSI-SDK/commit/b392ca521b676ce2c578ab507dcc444c45881033))

### Features

- Add RSA support ([6bbd283](https://github.com/Sphereon-Opensource/SSI-SDK/commit/6bbd283e82ee33a11feb8ad8346776d0948dcb80))

## 0.9.1 (2022-12-16)

**Note:** Version bump only for package @sphereon/bls-did-provider-key

# [0.8.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.7.0...v0.8.0) (2022-09-03)

**Note:** Version bump only for package @sphereon/bls-did-provider-key

# [0.7.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.6.0...v0.7.0) (2022-08-05)

**Note:** Version bump only for package @sphereon/bls-did-provider-key

# [0.6.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.5.1...v0.6.0) (2022-07-01)

**Note:** Version bump only for package @sphereon/bls-did-provider-key
