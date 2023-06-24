# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [0.12.1](https://github.com/Sphereon-OpenSource/ssi-sdk/compare/v0.12.0...v0.12.1) (2023-06-24)


### Bug Fixes

* Fix EC handling for JWKs ([7be20f5](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/7be20f57d6b7d4b7ebf5a2e9b432da34f8f98436))
* Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
* Make sure we set the saltLength for RSA PSS ([51ae676](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/51ae6769386866771c68c7b7806a75b62a9d5ec1))
* Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-OpenSource/ssi-sdk/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))





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
