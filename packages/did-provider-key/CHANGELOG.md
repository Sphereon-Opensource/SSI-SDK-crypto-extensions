# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.17.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.16.0...v0.17.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.did-provider-key

# [0.16.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.15.0...v0.16.0) (2024-01-13)

### Bug Fixes

- did:key ebsi / jcs codec value was wrong ([a71279e](https://github.com/Sphereon-Opensource/SSI-SDK/commit/a71279e3b79bff4add9fa4c889459264419accc6))

### Features

- ebsi resolver. Add support for fallback/multiple registries, so a client isn't required to specify a registry perse ([dedd959](https://github.com/Sphereon-Opensource/SSI-SDK/commit/dedd95986debbe2822fef298b4bc91a252e64ef7))

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
- add ebsi v1 did driver ([8869643](https://github.com/Sphereon-Opensource/SSI-SDK/commit/88696430b671d46127d3dcff41936cbcb1a66d4c))
- add key utils package for common key functions ([0543254](https://github.com/Sphereon-Opensource/SSI-SDK/commit/0543254d14b4ba54adeeab944315db5ba6221d47))
- Move to pnpm from yarn ([6ed9bd5](https://github.com/Sphereon-Opensource/SSI-SDK/commit/6ed9bd5fe72645364e631be1628710f57d5deb19))
- Reorganize SSI-SDK crypto extensions and DIDs ([5578914](https://github.com/Sphereon-Opensource/SSI-SDK/commit/55789146f48b31e8efdd64afa464a42779a2137b))

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
