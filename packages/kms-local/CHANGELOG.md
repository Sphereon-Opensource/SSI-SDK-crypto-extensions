# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.20.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.19.0...v0.20.0) (2024-06-13)

### Bug Fixes

- added a few fixes and type definitions ([7040799](https://github.com/Sphereon-Opensource/SSI-SDK/commit/7040799e509da9546ca3c52c1a209a5a7679ac13))

### Features

- (wip) added list keys functionality. the kms-local function works but we face error on key-manager level ([bde93d3](https://github.com/Sphereon-Opensource/SSI-SDK/commit/bde93d3e4d131ac0257ae4c04671be6bce014b1e))

# [0.19.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.2...v0.19.0) (2024-04-25)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.kms-local

## [0.18.2](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.1...v0.18.2) (2024-04-24)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.kms-local

## [0.18.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.18.0...v0.18.1) (2024-04-04)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.kms-local

# [0.18.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.17.0...v0.18.0) (2024-03-19)

### Bug Fixes

- Make sure bbs-sig packages are peer deps, because of heir poor Windows and RN support ([32d6bd9](https://github.com/Sphereon-Opensource/SSI-SDK/commit/32d6bd9c0857f431c9b7a845e73437536f2d377b))
- Make sure secp256k1 keys are compressed ([15493c1](https://github.com/Sphereon-Opensource/SSI-SDK/commit/15493c1b310c34bb70f6140c26819252e1b7b697))

# [0.17.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.16.0...v0.17.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.kms-local

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

### Features

- Add verification functions to KMS (only RSA for now) ([8f58f23](https://github.com/Sphereon-Opensource/SSI-SDK/commit/8f58f2308bc0dd612d1bb47b5ae05e8b67cf2efb))

# [0.13.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.12.1...v0.13.0) (2023-07-30)

### Features

- Add agent resolver method ([3c7b21e](https://github.com/Sphereon-Opensource/SSI-SDK/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))
- Add support for RSA key generation and RSA to JWK ([75ba154](https://github.com/Sphereon-Opensource/SSI-SDK/commit/75ba154bb110a50a1892a5308627895a93f527a4))

## [0.12.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.12.0...v0.12.1) (2023-06-24)

### Bug Fixes

- Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-Opensource/SSI-SDK/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
- Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-Opensource/SSI-SDK/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))

# [0.12.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.11.0...v0.12.0) (2023-05-07)

### Features

- Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-Opensource/SSI-SDK/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))

# [0.11.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.2...v0.11.0) (2023-04-30)

### Features

- Add 2020 ed25519 support. ([50cc65e](https://github.com/Sphereon-Opensource/SSI-SDK/commit/50cc65e249001809c18d1ef0e2e751c8428ccc70))
- add key utils package for common key functions ([0543254](https://github.com/Sphereon-Opensource/SSI-SDK/commit/0543254d14b4ba54adeeab944315db5ba6221d47))
- Move to pnpm from yarn ([6ed9bd5](https://github.com/Sphereon-Opensource/SSI-SDK/commit/6ed9bd5fe72645364e631be1628710f57d5deb19))
- Reorganize SSI-SDK crypto extensions and DIDs ([5578914](https://github.com/Sphereon-Opensource/SSI-SDK/commit/55789146f48b31e8efdd64afa464a42779a2137b))

## [0.10.2](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.1...v0.10.2) (2023-03-11)

**Note:** Version bump only for package @sphereon/bls-kms-local

## [0.10.1](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.10.0...v0.10.1) (2023-03-10)

**Note:** Version bump only for package @sphereon/bls-kms-local

# [0.10.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.9.1...v0.10.0) (2023-03-09)

### Bug Fixes

- Fix kms string used when importing keys, whilst we are already the KMS. Fix alias/kid handling for RSA keys ([20ed263](https://github.com/Sphereon-Opensource/SSI-SDK/commit/20ed26354c4fa10d1361405378acafb99d42a6ba))
- move to maintained isomorphic-webcrypto ([#2](https://github.com/Sphereon-Opensource/SSI-SDK/issues/2)) ([b392ca5](https://github.com/Sphereon-Opensource/SSI-SDK/commit/b392ca521b676ce2c578ab507dcc444c45881033))

### Features

- Add RSA support ([6bbd283](https://github.com/Sphereon-Opensource/SSI-SDK/commit/6bbd283e82ee33a11feb8ad8346776d0948dcb80))
- fix sigs ([5c64585](https://github.com/Sphereon-Opensource/SSI-SDK/commit/5c645857e8e7d6c24e02332d1a4183ebf0f88c44))
- make sure signature is base64url and not base64urlpad ([3b31a2f](https://github.com/Sphereon-Opensource/SSI-SDK/commit/3b31a2fb86080e7d09a343c99ac47c12753425a3))
- make sure signature is base64url and not base64urlpad ([086d280](https://github.com/Sphereon-Opensource/SSI-SDK/commit/086d280627c9ce0e9f862fb4b2577acd0bfad47c))
- make sure signature is base64url and not base64urlpad ([aba391b](https://github.com/Sphereon-Opensource/SSI-SDK/commit/aba391b900c21204f78ded098def5eb92077ef1c))
- make sure signature is base64url and not only base64 ([6a7f915](https://github.com/Sphereon-Opensource/SSI-SDK/commit/6a7f915684cf3df1182a44870a92981fe62edfa2))
- replace jsencrypt with isomorphic-webcrypto ([4a7ca7a](https://github.com/Sphereon-Opensource/SSI-SDK/commit/4a7ca7acc995d5050c159a89f2a7dee3f71e67af))

## 0.9.1 (2022-12-16)

**Note:** Version bump only for package @sphereon/bls-kms-local

# [0.8.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.7.0...v0.8.0) (2022-09-03)

**Note:** Version bump only for package @sphereon/bls-kms-local

# [0.7.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.6.0...v0.7.0) (2022-08-05)

**Note:** Version bump only for package @sphereon/bls-kms-local

# [0.6.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.5.1...v0.6.0) (2022-07-01)

**Note:** Version bump only for package @sphereon/bls-kms-local
