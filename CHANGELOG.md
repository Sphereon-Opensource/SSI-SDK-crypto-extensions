# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.28.0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/compare/v0.27.0...v0.28.0) (2025-03-14)

### Bug Fixes

- Fixed jwt decoding ([8c2ba79](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/8c2ba7951e23650a8b2df0a20db13109357fc284))
- Fixed jwt type ([67b5af1](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/67b5af10a1af66aaa03c225c0303cd323a2d5c80))
- merging issue ([f1862bf](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/f1862bf57b3488fffaad2222174ed6927e5e3a05))
- potential undefined idOpts in legacy conversion ([7161cdc](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/7161cdca6d24315f01b785ed437edb27ef49f0f3))

### Features

- Improve managed kid resolution in case we encounter a DID ([83d966d](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/83d966d3b3b7a873f2c6aad441c05f32b16cc272))

# [0.27.0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/compare/v0.26.0...v0.27.0) (2024-12-05)

### Bug Fixes

- add some additional tests for did:key ([59b1161](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/59b11614f67416a763b3f8eaedf0aad925666ec8))
- default crypto engine ([503768f](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/503768f6fa976585b6b2ae2c63652bad556cce20))
- make sure we return the chain back in the original order ([683ddb7](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/683ddb776b3b6d8e54bcf944cc4c32c7a7fecefc))
- Move away from using crypto.subtle for signature verifications, as it is too problematic in React-native. Replaced with audited noble implementations ([69ec9a6](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/69ec9a68a655eb34060a70ba64d83ef0df770bac))
- remove random uuid ([b968166](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/b968166eadb5f78d276657b89c6930c0fb97f08d))
- update x.509 test with latest cert ([175cd80](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/175cd8041e4b7f8c761b5519d44ec0602e2be88c))
- update x.509 x5c order ([3dbfe73](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/3dbfe73665f102d9c51e180199348cc8288f2a9c))

### Features

- Allow non trusted certs ([b1c6ff7](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/b1c6ff753ba397e3d7732d768c23699e83047f6d))
- Allow non trusted certs ([8416546](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/84165465629cefca755c7a64a7626278618ebb8f))
- implement azure keyvault rest client ([dc69703](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/dc697034da974e88d933088f5aaf551c27845a49))
- make sure we convert JWK claims from base64 to base64url if they are not spec compliant ([918677b](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/918677bc9cf062c0eff7d6eec5e83ee50d47f4e7))
- New x.509 validation implementation. Less features than previous version, but should work on RN ([c11d735](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/c11d7358925eebdb63db63a28a97f7e179ae0246))

# [0.26.0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/compare/v0.25.0...v0.26.0) (2024-11-26)

### Bug Fixes

- Add support for P-384/521 external JWKs ([7f4a809](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/7f4a8090121ee2aedae64af06ccc42e7b069bd6b))
- Make sure we can use thumbprints for signing ([679d3e7](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/679d3e73ca984a57afda9c55222a9fc596a623ec))
- Make sure we can use thumbprints for signing ([e64b326](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/e64b3263f83eaa88b75a57d2d3bae8f5e0575c6d))

### Features

- Add OYD DID support in enum ([01fe1d0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/01fe1d0168b6b8da929a85586eedb7d398a239a3))
- create kms-azure plugin structure ([61e1a61](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/61e1a61f7442acf376d5cc6e39cdacdc336b8aa3))

# [0.25.0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/compare/v0.24.0...v0.25.0) (2024-10-28)

### Bug Fixes

- added @trust/keyto to dependencies of key-utils ([bc5d6f6](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/bc5d6f68f74d8206794c611d5f9616a1f99bc822))
- added @trust/keyto to dependencies of key-utils ([6bb8d9e](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/6bb8d9eda667782b6fec8defd100a0b5ae2de852))
- applied importProvidedOrGeneratedKey in KeyDidProvider ([841a1da](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/841a1daf9ad9a3eef8cbad89ac2624c7ec253ca0))
- fixed didManagerCreate test ([b3b6756](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/b3b6756b3ba231c9721a6d104bb48c46b7dd13d4))
- lockfile ([73415ed](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/73415eda87e71d990e8d7726fbef7c1eb5072280))
- musapKMS improved determineAlgorithm handling ([24d8218](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/24d8218e0397ac4a8d0023533dbb807be0c8fa98))
- reverted dependency update of ssi-types in key-utils module ([4150b25](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/4150b2513c8d01dfcdf26ff78c9951b4147aa884))
- reverted dependency update of ssi-types in key-utils module ([1741bda](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/1741bda55fad424c52b96fbba0e81da384e8777d))
- u8aintarrays do not work with REST ([8c68022](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/8c68022a999ae67c1b06d9ba80ec40a92e9db8a2))
- **workaround:** Workaround (downgrade) for nist-weierstrauss being ESM only. refs [#19](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/issues/19) (should have a proper solution soon) ([aff05cf](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/aff05cf26ef7a6092d748fc3633ca48e997a4797))

### Features

- Add JWS signature verification; Add cose key conversions and resolution (managed and external) ([9f76393](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/9f7639322d825bd7ec0a276adfb6ab4a934fc571))
- Add support for setting or inferring kid and issuer. Which will be handy for JWS signing. Also split managed functions into separate functions, like we do for the external identifier resolution. ([c17edaf](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/c17edaf8f7fa14a0a998d7ea5b5370e5014dbc0b))
- Add support to convert any identifier resolution to JWK and Key resolution ([60da6b8](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/60da6b8eefe5f2a07af102eae64902b81256b089))
- added calculation and querying based on jwk thumbprints ([5ce83cc](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/5ce83cca64d55b664a2b0e6eb04660d299e2655c))
- added managed issuer identifier resolution ([d5ca58e](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/d5ca58e02c86702ed8f18374d65b78cd337dd7c2))
- added MusapKeyManagerSystem ([5841d67](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/5841d677fad29bb770f7157cd3f7a77e634b27f9))
- Added x509 validateX5cCertificateChain & validatePEMCertificateChain functions ([3706e31](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/3706e313c95bb26ee397c3fff6034e31a537b563))
- Allow main managed identifier get method to be lazy when a resolved identifier is passed in ([28fb763](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/28fb763f611e845d64342c8f726cea9fd38bd95e))
- Allow main managed identifier get method to be lazy when a resolved identifier is passed in ([7d4fa81](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/7d4fa81b44cfae44a23339125076bf825503b887))
- Allow to cleanup keys and have ephemeral keys. Remove dep on kms-local from KMS. Always calculate jwkThumbprints no matter the KMS used ([94414ff](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/94414ffe62f1bb2192506b1ab81441077d92712d))
- also allow passing in a resolved identifier next to identifier opts, so we do not have to resolve twice ([70d2d15](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/70d2d15cb5456d03ecc652092adbe3fba73a4c3d))
- Create seperate function to handle KMS managed identifiers of different types as the assumption always was DIDs ([944b425](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/944b42566461a125a4e14e7c0caba94040fac862))
- Expose managed identifier lazy result method, as we are using lazy resolution more and more ([b2c8065](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/b2c80655b05eec627f2f3d957cece1b6468375cf))
- Expose subject alternative names. Make getting the public key JWK more resilient. Allow to blindly trust certificates for testing purposes (only when x5c has 1 element!) as we perform all kinds of checks including CA certificate extension verifications in the chain ([675d6cb](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/675d6cb99e1ff87da59f37880a4c3b1f6d3809e5))
- External resolution of keys and validations for DIDs and x5c ([01db327](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/01db32715f7e7a95b57e07c23b7f3cc5b6ffa578))
- Have a method on the Key Management System as well as a separate function to get a named or the default KMS. Remove dep/enum for kms local. We only have KMSs names at runtime. We should not rely on static KMS names ever! ([c0ca69f](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/c0ca69fe0f10cfd9cdafa94b7af31a6cf6100680))
- JWE JWT compact agent methods ([6324f97](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/6324f978ae1b08c5dd5e116129166f40c8e3a58f))
- New JWS signature service that makes use of the managed identifier resolution, allowing for easier and more flexible JWT signing. ([941996e](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/941996ea69fc042680b29d39667b92b56690887f))

### Reverts

- Revert "chore: Allow default values for kms as kms is not optional in Veramo APIs" ([708742c](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/708742c013bc9e8cff9217e1eaff746ae0f8af00))

# [0.24.0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/compare/v0.23.0...v0.24.0) (2024-08-01)

### Bug Fixes

- added createKey functionality ([fcb9e82](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/fcb9e826072638ea775fd60a65bdc076ec35fed7))
- added enable sscd to musap react native kms ([da8a411](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/da8a4112d46c652b5681f569ac0069143843ff9c))
- **breaking:** Remove BLS crypto from Mattr for now. It is not very well maintained, and is proving to be very difficult in both Windows and React-Native environments. Will be replaced later with a different implementation ([e097e25](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/e097e2502ce7baa38f78f6afd1924d989f918dea))
- Fix key usages for jwks when importing keys ([c473572](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/c473572dc14105fec4626f596b21aebf180079da))
- fixed the sign function for musap rn kms ([e3318e6](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/e3318e6711148a75973810642c6055a4b860c56b))
- modified the decoding for sign in the musap module ([8561b0d](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/8561b0d071ef62423e8f99850b443fd2f8e5d764))
- modified the decoding for sign in the musap module ([64a53c5](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/64a53c5a8222f8f2a879368880ad843e7d4f3c54))
- modified the decoding for sign in the musap module ([34bba55](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/34bba55c4ea4e3edd78aa0be4b46b95cf2ff4919))
- modified the decoding for sign in the musap module ([e2a76a7](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/e2a76a7f7bbdd8106815c2e2f35b2dd9783ee9a5))
- modified the decoding for sign in the musap module ([7b6e68f](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/7b6e68fd26448f4aa1d36ca47e40067356585a94))
- updated musap kms with recent changes from the musap react native lib ([b1518de](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/b1518de689b28ee1da85337f1b828afb02a41f5d))

### Features

- (WIP) added MusapKeyManagerSystem ([f55926f](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/f55926f788f20ce2ab1ebafbcb305c7b361bb569))
- (WIP) added MusapKeyManagerSystem ([809846d](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/809846d2a9cacbb084ba2bc7924df33df254b1b7))
- added build script and android directory to musap-rn-kms module ([9be5fb0](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/9be5fb0d739d457407eccdd1719c397274189206))
- added delete function ([ab72368](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/ab72368f603258c588d47857b753f42e6bba8390))
- added mapper function for create key in musap kms and added the option to enable certain sscd's in the constructor ([db5c8d3](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/db5c8d3d60cc00094b91e6c3675d478c16d95555))
- added sign function ([62dc3ab](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/62dc3ab3d7721255d4ed6b9edf9cc18be69bc402))
- Improve kid determination. Rename most `kid` arguments to kmsKeyRef, as these are only the internal KMS kids. Preventing confusion. Improve did functions to accept object args. ([22f465c](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/22f465c9b7bfc5b5f628557c6a0631ae5817d444))
- remove isomorphic-webcrypto ([1adc1fe](https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/commit/1adc1fee3a80c4b7df69eca46e5c7469d6ce9f71))

# [0.23.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.22.0...v0.23.0) (2024-07-23)

### Bug Fixes

- Did web keys and services options/args were not taken into account ([fb37ba0](https://github.com/Sphereon-Opensource/veramo-BBS/commit/fb37ba070612a5a868916a53b5cbd37d0e7e92dd))
- did web resolution from identifier was not taking keys into account that had no purpose set ([8447426](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8447426c7be54f81398c77f3a29c029c7250380d))
- did web resolution from identifier was not taking keys into account that had no purpose set ([980075b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/980075b6ee8702b0a2fa31779aa21420827dda1d))
- get or create primary identifier was incorrectly constructing the identifier provider from the DID method ([d89542e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d89542e18e3a48a5ad048000330d97ecf8d861e5))
- get or create primary identifier was not searching for the correct DID methods ([8b1aad7](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8b1aad7d0f3de534266972023b23c8f3881fd106))

### Features

- generate key when private keys is not provided ([090b8fa](https://github.com/Sphereon-Opensource/veramo-BBS/commit/090b8fa20ee4aa2da4ca68a3b1bbe9bd00925cc0))
- Make key/vm from identifier/did functions more future proof and add option to search for controller keys and key types ([f691789](https://github.com/Sphereon-Opensource/veramo-BBS/commit/f6917899680c1f39a98a0afbf181e821edadd4a3))

# [0.22.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.21.0...v0.22.0) (2024-07-02)

### Bug Fixes

- better local DID Document conversion from identifiers ([e332562](https://github.com/Sphereon-Opensource/veramo-BBS/commit/e332562ee79a57bd7a2b57426dcd08373f91195c))
- determine kid function can have a null verification method which was not taken into account ([d80a945](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d80a9455ae6ff2eccf9a6001e12d371bad8dd742))
- getKey method was not looking at existing vms or purpose metadata values ([36619d6](https://github.com/Sphereon-Opensource/veramo-BBS/commit/36619d6db64fbb3b071f71a2687d60243fe4bcd6))
- getKey method was not working well with did#vm or #vm key ids ([b04eb3f](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b04eb3fee9406bc5c550d392fd97c9a31455b9be))
- Key metadata was switched for Secp256k1 and Secp256r1 keys ([ae174aa](https://github.com/Sphereon-Opensource/veramo-BBS/commit/ae174aa833a4989f921b92f2778bbeb63d867d3b))
- kid determination of a key should look for jwk thumbprint as well ([d00e984](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d00e98446601d7a2593db32529ba958629fe4005))
- our exported JWK depended on another lib, which is not needed. Also was not compatible with Jose, which is heavily used ([8b20d61](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8b20d616c87a350a42d72bf98ab13311e8f248ee))
- x5c is an array in a JWK ([58f607f](https://github.com/Sphereon-Opensource/veramo-BBS/commit/58f607f82194afe1907e0d13909f1fbd9bff7d7f))

### chore

- remove did-provider-ebsi in favor of ebsi-support, which can also handle everything the old provider did ([5299044](https://github.com/Sphereon-Opensource/veramo-BBS/commit/529904454eae1da87382ad92cc65e034770d9b56))

### Features

- Add service and key for EBSI DIDs ([4ec6f18](https://github.com/Sphereon-Opensource/veramo-BBS/commit/4ec6f18e5e8f5b90de09c80eda7c44cf9f748985))
- Add support to find keys by thumbprint, and not have to resolve to DID resolution in all cases ([d37c772](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d37c772b0eb3ce65a1e0a5f99b97acf641515d6b))
- Added getAuthenticationKey getPrimaryIdentifier & createIdentifier to did-utils ([7360ab6](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7360ab606b6b22a9c8cd259e1994198a04a4ab3e))

### BREAKING CHANGES

- remove @sphereon/ssi-sdk-ext.did-provider-ebsi, which has been replaced with @sphereon/ssi-sdk.ebsi-support

# [0.21.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.20.0...v0.21.0) (2024-06-19)

### Bug Fixes

- Multiple DID EBSI fixes ([131faa0](https://github.com/Sphereon-Opensource/veramo-BBS/commit/131faa0b583063cb3d8d5e77a33f337a23b90536))

### Features

- Ensure we can actually pass in bearer tokens & misc cleanups ([4abc507](https://github.com/Sphereon-Opensource/veramo-BBS/commit/4abc507e2b0dda53cc77cb00a55d4b432e6c38de))

# [0.20.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.19.0...v0.20.0) (2024-06-13)

### Bug Fixes

- added a few fixes and type definitions ([7040799](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7040799e509da9546ca3c52c1a209a5a7679ac13))
- added keyManagerListKeys binding ([e2f723b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/e2f723b3412266d30405909b7822efc4a94b051d))
- Bugfix creating eth transactions ([1d2e04d](https://github.com/Sphereon-Opensource/veramo-BBS/commit/1d2e04da8e682ffa725f280d3863fc66a4fe0f9a))
- fix base64url sanitizing ([473c028](https://github.com/Sphereon-Opensource/veramo-BBS/commit/473c0281e8c24565bb0ada0d335d32014453294d))
- Fixed broken tests ([07d320a](https://github.com/Sphereon-Opensource/veramo-BBS/commit/07d320a4a04bfd41093e6ed7133b81134aa6a381))

### Features

- (wip) added list keys functionality. the kms-local function works but we face error on key-manager level ([bde93d3](https://github.com/Sphereon-Opensource/veramo-BBS/commit/bde93d3e4d131ac0257ae4c04671be6bce014b1e))
- Added secp256r1 key to createIdentifier() method ([81fff51](https://github.com/Sphereon-Opensource/veramo-BBS/commit/81fff5196b74fe3f579407a19f60cb67db554bbb))
- Implemented conversion of public keys, rpc service and documentation ([b0ac3b5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b0ac3b5d9fea4a4d37d6175057ff131ffee38307))
- Implemented integration of the ebsi rpc service with the ebsi did provider ([3c1ef0d](https://github.com/Sphereon-Opensource/veramo-BBS/commit/3c1ef0da981f86f0b8241d5fcab65d32f03584ba))

# [0.19.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.18.2...v0.19.0) (2024-04-25)

### Features

- Added secp256r1 key to createIdentifier() method ([f8da68d](https://github.com/Sphereon-Opensource/veramo-BBS/commit/f8da68d0b79a8977128bcfa16673ab8bf8547b58))

## [0.18.2](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.18.1...v0.18.2) (2024-04-24)

**Note:** Version bump only for package @sphereon/ssi-sdk-ext.workspace

## [0.18.1](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.18.0...v0.18.1) (2024-04-04)

### Bug Fixes

- Padding had incorrect length comparison ([d141050](https://github.com/Sphereon-Opensource/veramo-BBS/commit/d141050b31bd1b846a2f5471a2e9673895e1239b))

# [0.18.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.17.0...v0.18.0) (2024-03-19)

### Bug Fixes

- Key did provider fixes for invalid did:key encodings ([194c480](https://github.com/Sphereon-Opensource/veramo-BBS/commit/194c4808221ef232b0791ce04ce48459980611a2))
- Make sure bbs-sig packages are peer deps, because of heir poor Windows and RN support ([32d6bd9](https://github.com/Sphereon-Opensource/veramo-BBS/commit/32d6bd9c0857f431c9b7a845e73437536f2d377b))
- Make sure secp256k1 keys are compressed ([15493c1](https://github.com/Sphereon-Opensource/veramo-BBS/commit/15493c1b310c34bb70f6140c26819252e1b7b697))
- unknown point format ([b25d6de](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b25d6de6e8c938d36cf2aa6e8679a549bd41aea5))

### Features

- Ensure proper key type is used for did:key in case codeName is JCS/EBSI ([af11a99](https://github.com/Sphereon-Opensource/veramo-BBS/commit/af11a99b0912d911e2d11fad94e7ccf02068afbd))

# [0.17.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.16.0...v0.17.0) (2024-02-29)

### Bug Fixes

- Make sure we are more strict on hex key lengths for Secp256r1/k1 ([2f5bf1f](https://github.com/Sphereon-Opensource/veramo-BBS/commit/2f5bf1f23f7956bc4429a5e82bda1ac167842344))

### Features

- Add OwnYouData DID plugin (temp until upstream publishes it) ([6b428e2](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6b428e242d968594b29938e4861f44ae3e5a7106))

# [0.16.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.15.0...v0.16.0) (2024-01-13)

### Bug Fixes

- did:key ebsi / jcs codec value was wrong ([a71279e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/a71279e3b79bff4add9fa4c889459264419accc6))
- error handling fixed for did:ebsi ([6d37523](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6d375237fac7eeb339e08465deb0065e0dec069a))

### Features

- Add private key to JWK support for Secp256k/r1 ([f278967](https://github.com/Sphereon-Opensource/veramo-BBS/commit/f2789670fb2dcae8f07c38c5a92eeae2eb9780d0))
- ebsi resolver. Add support for fallback/multiple registries, so a client isn't required to specify a registry perse ([dedd959](https://github.com/Sphereon-Opensource/veramo-BBS/commit/dedd95986debbe2822fef298b4bc91a252e64ef7))

# [0.15.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.14.1...v0.15.0) (2023-09-30)

### Features

- check whether resolution is configured properly ([01a693b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/01a693b94cd612826312168973caf15b0441ebf0))

## [0.14.1](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.14.0...v0.14.1) (2023-09-28)

### Bug Fixes

- decompress comppressed secp256k1 keys when creating JWK ([e3c4771](https://github.com/Sphereon-Opensource/veramo-BBS/commit/e3c47715c8d751bc2ec75bdd1ed1e4965650c947))
- decompress comppressed secp256k1 keys when creating JWK ([bcdd47c](https://github.com/Sphereon-Opensource/veramo-BBS/commit/bcdd47c0526236cf1b7c3533a7047ebb23204a66))
- decompress comppressed secp256k1 keys when creating JWK ([31bacfb](https://github.com/Sphereon-Opensource/veramo-BBS/commit/31bacfb4c04e9b4363a4ef6e4e71a8cf7c1daced))
- public key mapping updates, fixing ed25519 with multibase encoding ([489d4f2](https://github.com/Sphereon-Opensource/veramo-BBS/commit/489d4f20e0f354eb50b1a16a91472d4e85588113))

# [0.14.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.13.0...v0.14.0) (2023-08-09)

### Bug Fixes

- Allow also for local did resolution ([0f92566](https://github.com/Sphereon-Opensource/veramo-BBS/commit/0f92566758eab0fe7edbf3ac8f04c32f6d9fdbb7))
- Allow also for local did resolution ([a678459](https://github.com/Sphereon-Opensource/veramo-BBS/commit/a678459a74b6b8a39f5b2229e790ca06a346d93e))
- Allow also for local did resolution ([91def9c](https://github.com/Sphereon-Opensource/veramo-BBS/commit/91def9c446849521f5e9da5beb07bab6871501d1))
- RSA import fixes ([1e78d70](https://github.com/Sphereon-Opensource/veramo-BBS/commit/1e78d70679ce8a70d82d2b7320c6f7489ff1a870))
- RSA import fixes ([77704a2](https://github.com/Sphereon-Opensource/veramo-BBS/commit/77704a2064e1c1d3ffc23e580ddbb36063fc70ae))
- RSA import fixes ([52c560b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/52c560b4d4fef999554ec00130cf7136dc2db1c6))
- update varint import ([c35849c](https://github.com/Sphereon-Opensource/veramo-BBS/commit/c35849cbca0d12aaa9da1e12979823072a023061))

### Features

- Add verification functions to KMS (only RSA for now) ([a555f11](https://github.com/Sphereon-Opensource/veramo-BBS/commit/a555f115901f325fbee26be5aeda23f808b48a1d))
- Add verification functions to KMS (only RSA for now) ([8f58f23](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8f58f2308bc0dd612d1bb47b5ae05e8b67cf2efb))
- Do not resolve DIDs when a DID doc is provided already when matching local keys ([b5b7f76](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b5b7f76496e328e264aa38f351f5a64c4ca03dba))

# [0.13.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.12.1...v0.13.0) (2023-07-30)

### Features

- Add agent resolver method ([462b5e3](https://github.com/Sphereon-Opensource/veramo-BBS/commit/462b5e33d31bfdc55bc4d8cf05868a4c945ea386))
- Add agent resolver method ([3c7b21e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/3c7b21e13538fac64581c0c73d0450ef6e9b56f0))
- Add DID web provider, with RSA and multi key import support ([8335fbe](https://github.com/Sphereon-Opensource/veramo-BBS/commit/8335fbe16e4a7740a11e225c99afb516c305d27f))
- Add support for RSA key generation and RSA to JWK ([75ba154](https://github.com/Sphereon-Opensource/veramo-BBS/commit/75ba154bb110a50a1892a5308627895a93f527a4))
- Allow to define controller key when importing keys for a did:web ([89b4916](https://github.com/Sphereon-Opensource/veramo-BBS/commit/89b4916d5496decd38e91c7962f9045d835393a8))
- Check also for other supported encryption algorithms when JWK use property is used ([36a8ae4](https://github.com/Sphereon-Opensource/veramo-BBS/commit/36a8ae45105791464432eb287988976b1ddfdb1e))
- Identifier to DID Document and DID resolution ([76e7212](https://github.com/Sphereon-Opensource/veramo-BBS/commit/76e7212cd6f7f27315d6b6bfdb17154124f3158e))

## [0.12.1](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.12.0...v0.12.1) (2023-06-24)

### Bug Fixes

- Fix EC handling for DID resolution ([5f3d708](https://github.com/Sphereon-Opensource/veramo-BBS/commit/5f3d70898783d56f5aa7a36e4fd56faf5907dbeb))
- Fix EC handling for JWKs ([9061e29](https://github.com/Sphereon-Opensource/veramo-BBS/commit/9061e2968005931127c52febbb3326fddcd62fb2))
- Fix EC handling for JWKs ([b60825b](https://github.com/Sphereon-Opensource/veramo-BBS/commit/b60825b155971dc8b01d2b4779faf71cecbacfa6))
- Fix EC handling for JWKs ([7be20f5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7be20f57d6b7d4b7ebf5a2e9b432da34f8f98436))
- Fix EC handling for JWKs ([dd423f2](https://github.com/Sphereon-Opensource/veramo-BBS/commit/dd423f24eff5fcc41a3b72c15d62d7e478fbe9b9))
- fix GH action ([2d8d6aa](https://github.com/Sphereon-Opensource/veramo-BBS/commit/2d8d6aaa376a1533ad2bcc3a7b886b65f8eaa293))
- Fixes in JWK handling ([f5cd4dd](https://github.com/Sphereon-Opensource/veramo-BBS/commit/f5cd4ddd4f0cd0f155dcbf3a7e8b43c89b97cacb))
- Make sure we set the saltLength for RSA PSS ([51ae676](https://github.com/Sphereon-Opensource/veramo-BBS/commit/51ae6769386866771c68c7b7806a75b62a9d5ec1))
- Make sure we set the saltLength for RSA PSS ([e19ed6c](https://github.com/Sphereon-Opensource/veramo-BBS/commit/e19ed6c3a7b8454e8074111d33fc59a9c6bcc611))

# [0.12.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.11.0...v0.12.0) (2023-05-07)

### Features

- Move mnemonic seed generator to crypto extensions ([748a7f9](https://github.com/Sphereon-Opensource/veramo-BBS/commit/748a7f962d563c60aa543c0c6900aa0c0daea42d))
- Move mnemonic seed generator to crypto extensions ([173ef88](https://github.com/Sphereon-Opensource/veramo-BBS/commit/173ef883deafa4c87f0d589963fb36ccb8789d1b))

# [0.11.0](https://github.com/Sphereon-Opensource/veramo-BBS/compare/v0.10.2...v0.11.0) (2023-04-30)

### Features

- Add 2020 ed25519 support. ([50cc65e](https://github.com/Sphereon-Opensource/veramo-BBS/commit/50cc65e249001809c18d1ef0e2e751c8428ccc70))
- Add EBSI LE DID Provider (does not persist into the registry yet) ([7a8cf56](https://github.com/Sphereon-Opensource/veramo-BBS/commit/7a8cf5687152ba0a7449d93eeb40289d6af07acf))
- add ebsi v1 did driver ([8869643](https://github.com/Sphereon-Opensource/veramo-BBS/commit/88696430b671d46127d3dcff41936cbcb1a66d4c))
- add key utils package for common key functions ([0543254](https://github.com/Sphereon-Opensource/veramo-BBS/commit/0543254d14b4ba54adeeab944315db5ba6221d47))
- allow default registry from environment for ebsi v1 did driver ([217dfc0](https://github.com/Sphereon-Opensource/veramo-BBS/commit/217dfc0d89a72229591be3313cb1e7f3eebb25ad))
- Move to pnpm from yarn ([6ed9bd5](https://github.com/Sphereon-Opensource/veramo-BBS/commit/6ed9bd5fe72645364e631be1628710f57d5deb19))
- Reorganize SSI-SDK crypto extensions and DIDs ([5578914](https://github.com/Sphereon-Opensource/veramo-BBS/commit/55789146f48b31e8efdd64afa464a42779a2137b))

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
