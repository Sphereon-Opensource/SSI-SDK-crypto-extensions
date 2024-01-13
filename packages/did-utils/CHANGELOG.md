# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.16.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.15.0...v0.16.0) (2024-01-13)

### Bug Fixes

- did:key ebsi / jcs codec value was wrong ([a71279e](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/a71279e3b79bff4add9fa4c889459264419accc6))

# [0.15.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.14.1...v0.15.0) (2023-09-30)

### Features

- check whether resolution is configured properly ([01a693b](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/01a693b94cd612826312168973caf15b0441ebf0))

## [0.14.1](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.14.0...v0.14.1) (2023-09-28)

### Bug Fixes

- public key mapping updates, fixing ed25519 with multibase encoding ([489d4f2](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/489d4f20e0f354eb50b1a16a91472d4e85588113))

# [0.14.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.13.0...v0.14.0) (2023-08-09)

### Bug Fixes

- Allow also for local did resolution ([0f92566](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/0f92566758eab0fe7edbf3ac8f04c32f6d9fdbb7))
- Allow also for local did resolution ([a678459](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/a678459a74b6b8a39f5b2229e790ca06a346d93e))
- Allow also for local did resolution ([91def9c](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/91def9c446849521f5e9da5beb07bab6871501d1))
- RSA import fixes ([77704a2](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/77704a2064e1c1d3ffc23e580ddbb36063fc70ae))

### Features

- Do not resolve DIDs when a DID doc is provided already when matching local keys ([b5b7f76](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/b5b7f76496e328e264aa38f351f5a64c4ca03dba))

# [0.13.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.12.1...v0.13.0) (2023-07-30)

### Features

- Add agent resolver method ([462b5e3](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/462b5e33d31bfdc55bc4d8cf05868a4c945ea386))
- Add agent resolver method ([3c7b21e](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))
- Check also for other supported encryption algorithms when JWK use property is used ([36a8ae4](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/36a8ae45105791464432eb287988976b1ddfdb1e))
- Identifier to DID Document and DID resolution ([76e7212](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/76e7212cd6f7f27315d6b6bfdb17154124f3158e))

## [0.12.1](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.12.0...v0.12.1) (2023-06-24)

### Bug Fixes

- Fix EC handling for DID resolution ([5f3d708](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/5f3d70898783d56f5aa7a36e4fd56faf5907dbeb))
- Fix EC handling for JWKs ([9061e29](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/9061e2968005931127c52febbb3326fddcd62fb2))
- Fix EC handling for JWKs ([b60825b](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/b60825b155971dc8b01d2b4779faf71cecbacfa6))
- Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
- Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))

# [0.12.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.11.0...v0.12.0) (2023-05-07)

### Features

- Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))

# [0.11.0](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/compare/v0.10.2...v0.11.0) (2023-04-30)

### Features

- add key utils package for common key functions ([0543254](https://github.com/Sphereon-OpenSource/ssi-sdk-crypto-extensions/commit/0543254d14b4ba54adeeab944315db5ba6221d47))

# [0.9.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.8.0...v0.9.0) (2023-03-09)

### Bug Fixes

- Fix DID handling in OP session ([926e358](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/926e358ef3eadf19fc3c8f7c9940fe6322c5ff85))
- fix private key hex from Pem ([0204094](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/0204094e7b7fd33314a31df5d06344f54e6f6442))

### Features

- allow existing did document for mapping ([5f183ce](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/5f183ce655a40332a65480634b356ae8fa4d7a84))
- allow existing did document for mapping ([4d82518](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/4d82518653ff456383561c22870856f110976aa0))
- did utils package ([d98b358](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/d98b358ff7f9c787667b4bf48fd748ae9f58197a))
- make sure the vc-handler-ld-local can deal with keys in JWK format ([26cff51](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/26cff511b345e412dc37586ef3c3c8fe678cd574))
- Update SIOP OP to be in line wiht latest SIOP and also supporting late binding of identifiers ([2beea04](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/2beea04a6604d82b12ecbc11e68a9f41775c22ed))

# [0.8.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.7.0...v0.8.0) (2022-09-03)

### Bug Fixes

- Remove most deps from ssi-sdk-core to prevent circular deps ([b4151a9](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/b4151a9cde3e5e5dcabb32367e7a6b6ab99cb6cd))

### Features

- Create common SSI types package ([0fdc372](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/0fdc3722e3bc47ac13c3c586535937fa1ebe6f68))

# [0.7.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.6.0...v0.7.0) (2022-08-05)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

# [0.6.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.5.1...v0.6.0) (2022-07-01)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

# [0.5.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.4.0...v0.5.0) (2022-02-23)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

# [0.4.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.3.4...v0.4.0) (2022-02-11)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

## [0.3.4](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.3.3...v0.3.4) (2022-02-11)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

## [0.3.1](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.3.0...v0.3.1) (2022-01-28)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

# [0.3.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.2.0...v0.3.0) (2022-01-16)

**Note:** Version bump only for package @sphereon/ssi-sdk-core

# [0.2.0](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.1.0...v0.2.0) (2021-12-16)

### Bug Fixes

- Multibase encoding didn't include the prefix char ([1be44b7](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/1be44b7f281b82370a59a321f25057bee34d58de))

### Features

- Add JSON-LD Credential and Presentation handling/sign support that is compatible with React-Native ([995f55e](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/995f55efd5237e3fbd76e6569e09ee3bbcbb686c))

# 0.1.0 (2021-11-26)

### Features

- Add ssi-sdk core module ([42a5b65](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/42a5b65fa3795284fc16b06d2a36c4bf4ea87668))
- Add workspace/lerna files and structures ([2c2b112](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/2c2b11244c2e5e3d2d1b1db76af3d86ec300bc72))
