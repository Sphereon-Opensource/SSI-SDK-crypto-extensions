# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.13.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.12.1...v0.13.0) (2023-07-30)


### Features

* Add agent resolver method ([462b5e3](https://github.com/Sphereon-Opensource/veramo-BBS/commit/462b5e33d31bfdc55bc4d8cf05868a4c945ea386))
* Add agent resolver method ([3c7b21e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))
* Add DID web provider, with RSA and multi key import support ([8335fbe](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8335fbe16e4a7740a11e225c99afb516c305d27f))
* Add support for RSA key generation and RSA to JWK ([75ba154](https://github.com/Sphereon-Opensource/veramo-BBS/commit/75ba154bb110a50a1892a5308627895a93f527a4))
* Allow to define controller key when importing keys for a did:web ([89b4916](https://github.com/Sphereon-Opensource/veramo-BBS/commit/89b4916d5496decd38e91c7962f9045d835393a8))
* Check also for other supported encryption algorithms when JWK use property is used ([36a8ae4](https://github.com/Sphereon-Opensource/veramo-BBS/commit/36a8ae45105791464432eb287988976b1ddfdb1e))
* Identifier to DID Document and DID resolution ([76e7212](https://github.com/Sphereon-Opensource/veramo-BBS/commit/76e7212cd6f7f27315d6b6bfdb17154124f3158e))





## [0.12.1](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.12.0...v0.12.1) (2023-06-24)


### Bug Fixes

* Fix EC handling for DID resolution ([5f3d708](https://github.com/Sphereon-Opensource/veramo-BBS/commit/5f3d70898783d56f5aa7a36e4fd56faf5907dbeb))
* Fix EC handling for JWKs ([9061e29](https://github.com/Sphereon-Opensource/veramo-BBS/commit/9061e2968005931127c52febbb3326fddcd62fb2))
* Fix EC handling for JWKs ([b60825b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b60825b155971dc8b01d2b4779faf71cecbacfa6))
* Fix EC handling for JWKs ([7be20f5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7be20f57d6b7d4b7ebf5a2e9b432da34f8f98436))
* Fix EC handling for JWKs ([dd423f2](https://github.com/Sphereon-Opensource/veramo-BBS/commit/dd423f24eff5fcc41a3b72c15d62d7e478fbe9b9))
* fix GH action ([2d8d6aa](https://github.com/Sphereon-Opensource/veramo-BBS/commit/2d8d6aaa376a1533ad2bcc3a7b886b65f8eaa293))
* Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-Opensource/veramo-BBS/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
* Make sure we set the saltLength for RSA PSS ([51ae676](https://github.com/Sphereon-Opensource/veramo-BBS/commit/51ae6769386866771c68c7b7806a75b62a9d5ec1))
* Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-Opensource/veramo-BBS/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))





# [0.12.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.11.0...v0.12.0) (2023-05-07)


### Features

* Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-Opensource/veramo-BBS/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))
* Move mnemonic seed generator to crypto extensions ([173ef88](https://github.com/Sphereon-Opensource/veramo-BBS/commit/173ef883deafa4c87f0d589963fb36ccb8789d1b))





# [0.11.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.10.2...v0.11.0) (2023-04-30)


### Features

* Add 2020 ed25519 support. ([50cc65e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/50cc65e249001809c18d1ef0e2e751c8428ccc70))
* Add EBSI LE DID Provider (does not persist into the registry yet) ([7a8cf56](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7a8cf5687152ba0a7449d93eeb40289d6af07acf))
* add ebsi v1 did driver ([8869643](https://github.com/Sphereon-Opensource/veramo-BBS/commit/88696430b671d46127d3dcff41936cbcb1a66d4c))
* add key utils package for common key functions ([0543254](https://github.com/Sphereon-Opensource/veramo-BBS/commit/0543254d14b4ba54adeeab944315db5ba6221d47))
* allow default registry from environment for ebsi v1 did driver ([217dfc0](https://github.com/Sphereon-Opensource/veramo-BBS/commit/217dfc0d89a72229591be3313cb1e7f3eebb25ad))
* Move to pnpm from yarn ([6ed9bd5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6ed9bd5fe72645364e631be1628710f57d5deb19))
* Reorganize SSI-SDK crypto extensions and DIDs ([5578914](https://github.com/Sphereon-Opensource/veramo-BBS/commit/55789146f48b31e8efdd64afa464a42779a2137b))





## [0.10.2](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.10.1...v0.10.2) (2023-03-11)

**Note:** Version bump only for package @sphereon/veramo-BBS-workspace

## [0.10.1](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.10.0...v0.10.1) (2023-03-10)

**Note:** Version bump only for package @sphereon/veramo-BBS-workspace

# [0.10.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.9.1...v0.10.0) (2023-03-09)

### Bug Fixes

- Fix kms string used when importing keys, whilst we are already the KMS. Fix alias/kid handling for RSA keys ([20ed263](https://github.com/Sphereon-Opensource/veramo-BBS/commit/20ed26354c4fa10d1361405378acafb99d42a6ba))
- move to maintained isomorphic-webcrypto ([feda9d1](https://github.com/Sphereon-Opensource/veramo-BBS/commit/feda9d15ff161f474aaac454e22fac11cf6562ba))
- move to maintained isomorphic-webcrypto ([53575be](https://github.com/Sphereon-Opensource/veramo-BBS/commit/53575be953cb7ac1e6683c7585366ce7f28e4359))
- move to maintained isomorphic-webcrypto ([4dbae0a](https://github.com/Sphereon-Opensource/veramo-BBS/commit/4dbae0a542bb52a9d81156286d39ac1d9eae7b23))
- move to maintained isomorphic-webcrypto ([1d69dd8](https://github.com/Sphereon-Opensource/veramo-BBS/commit/1d69dd82d1fa0090a9d40dae67c31b21fb98244a))
- move to maintained isomorphic-webcrypto ([d9e5a7e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d9e5a7e84c5b049401c53b1d4e0c48e74379a1f6))
- move to maintained isomorphic-webcrypto ([df0bb7a](https://github.com/Sphereon-Opensource/veramo-BBS/commit/df0bb7a787d8d228dc4e89b54c6bb3a9618185e1))
- move to maintained isomorphic-webcrypto ([fb6b0d9](https://github.com/Sphereon-Opensource/veramo-BBS/commit/fb6b0d92add1d47edc2a4fa41125616282e6cd90))
- move to maintained isomorphic-webcrypto ([dc767a3](https://github.com/Sphereon-Opensource/veramo-BBS/commit/dc767a325b4d55c06ff5ae0fb8f962b9b1909d64))
- move to maintained isomorphic-webcrypto ([#2](https://github.com/Sphereon-Opensource/veramo-BBS/issues/2)) ([b392ca5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b392ca521b676ce2c578ab507dcc444c45881033))

### Features

- Add RSA support ([881d794](https://github.com/Sphereon-Opensource/veramo-BBS/commit/881d794df934908242f9292cfd5be58fb16ee8a1))
- Add RSA support ([6bbd283](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6bbd283e82ee33a11feb8ad8346776d0948dcb80))
- fix sigs ([5c64585](https://github.com/Sphereon-Opensource/veramo-BBS/commit/5c645857e8e7d6c24e02332d1a4183ebf0f88c44))
- make sure signature is base64url and not base64urlpad ([3b31a2f](https://github.com/Sphereon-Opensource/veramo-BBS/commit/3b31a2fb86080e7d09a343c99ac47c12753425a3))
- make sure signature is base64url and not base64urlpad ([086d280](https://github.com/Sphereon-Opensource/veramo-BBS/commit/086d280627c9ce0e9f862fb4b2577acd0bfad47c))
- make sure signature is base64url and not base64urlpad ([aba391b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/aba391b900c21204f78ded098def5eb92077ef1c))
- make sure signature is base64url and not only base64 ([6a7f915](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6a7f915684cf3df1182a44870a92981fe62edfa2))
- replace jsencrypt with isomorphic-webcrypto ([4a7ca7a](https://github.com/Sphereon-Opensource/veramo-BBS/commit/4a7ca7acc995d5050c159a89f2a7dee3f71e67af))

## 0.9.1 (2022-12-16)

**Note:** Version bump only for package @sphereon/veramo-BBS-workspace

# [0.8.0](https://github.com/Sphereon-Opensource/SSI-SDK/compare/v0.7.0...v0.8.0) (2022-09-03)
