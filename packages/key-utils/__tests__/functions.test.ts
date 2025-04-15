import { JoseSignatureAlgorithm, JWK } from '@sphereon/ssi-types'
import * as u8a from 'uint8arrays'
import { generatePrivateKeyHex, jwkToRawHexKey, Key, padLeft, toJwk, verifyRawSignature } from '../src'


describe('functions: key generator', () => {
  it('Secp256k1 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Secp256k1)
    const key2 = await generatePrivateKeyHex(Key.Secp256k1)
    const key3 = await generatePrivateKeyHex(Key.Secp256k1)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Secp256k1 should result in hex length 64', async () => {
    expect((await generatePrivateKeyHex(Key.Secp256k1)).length).toBe(64)
  })

  it('Secp256r1 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Secp256r1)
    const key2 = await generatePrivateKeyHex(Key.Secp256r1)
    const key3 = await generatePrivateKeyHex(Key.Secp256r1)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Secp256r1 should result in hex length 64', async () => {
    expect((await generatePrivateKeyHex(Key.Secp256r1)).length).toBe(64)
  })

  it('Ed25519 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Ed25519)
    const key2 = await generatePrivateKeyHex(Key.Ed25519)
    const key3 = await generatePrivateKeyHex(Key.Ed25519)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Ed25519 should result in hex length 128', async () => {
    expect((await generatePrivateKeyHex(Key.Ed25519)).length).toBe(128)
  })
})
describe('functions: Leftpad', () => {
  it('should pad left to 64 chars when 62 chars are present', () => {
    const data = '2df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`00${data}`)
  })

  it('should not pad left to 64 chars when 64 chars are present', () => {
    const data = '002df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`${data}`)
  })

  it('should not pad left to 64 chars when more than 64 chars are present', () => {
    const data = '12345002df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`${data}`)
  })
})

describe('functions: verifySignature', () => {
  it('should convert jwk to hex', async () => {
    const publicKeyHex =
      '04c92ac29c7e06ba171a5ed3730f8a3243645a679827352963e2c7d7127537e6108ddd439d9d34f827f39cf3dc96471433c14f0022b55cba66d18c76687bdf94a7'
    const jwk: JWK = {
      alg: 'ES256',
      kid: 'https://oidf-dev.vault.azure.net/keys/test-key-39ca8c0e-1a7e-4356-8a61-f7edc80f3bbe/da7e0883d3f04a06a48ba40c0eaaa690',
      kty: 'EC',
      x: 'ySrCnH4GuhcaXtNzD4oyQ2RaZ5gnNSlj4sfXEnU35hA',
      y: 'jd1DnZ00+CfznPPclkcUM8FPACK1XLpm0Yx2aHvflKc',
    }

    const hex = await jwkToRawHexKey(jwk)
    expect(hex).toEqual(publicKeyHex)
  })

  it('should verify signature with secp256k1', async () => {
    const publicKeyHex =
      '04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152'
    const message = '4d7367' // from project whycheproof, in hex!
    const signatureHex =
      '109cd8ae0374358984a8249c0a843628f2835ffad1df1a9a69aa2fe72355545cac6f00daf53bd8b1e34da329359b6e08019c5b037fed79ee383ae39f85a159c6'
    await expect(
      verifyRawSignature({
        data: u8a.fromString(message, 'hex'),
        signature: u8a.fromString(signatureHex, 'hex'),
        key: toJwk(publicKeyHex, 'Secp256k1'),
      })
    ).resolves.toEqual(true)
  })

  it('should verify signature with secp256r1', async () => {
    const publicKeyHex =
      '042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e'
    const message = '313233343030' // from project whycheproof, in hex!
    const signatureHex =
      '2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76'
    await expect(
      verifyRawSignature({
        data: u8a.fromString(message, 'hex'),
        signature: u8a.fromString(signatureHex, 'hex'),
        key: toJwk(publicKeyHex, 'Secp256r1'),
      })
    ).resolves.toEqual(true)
  })

  it('should verify signature with ed25519', async () => {
    const publicKeyHex = '7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa'
    const message = '313233343030' // from project whycheproof, in hex!
    const signatureHex =
      '657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bf0cf5b3a289976458a1be6277a5055545253b45b07dcc1abd96c8b989c00f301'
    await expect(
      verifyRawSignature({
        data: u8a.fromString(message, 'hex'),
        signature: u8a.fromString(signatureHex, 'hex'),
        key: toJwk(publicKeyHex, 'Ed25519'),
      })
    ).resolves.toEqual(true)
  })

  it('should verify signature with rsa PSS', async () => {
    const publicKeyHex =
      'a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d510001'
    const message = '313233343030'
    const signatureHex =
      '5e91b5dcbf02d6f19621d41a83dc8f15ea83c0edb83765ef029b0acac2e1ec8918b1d2afe1fadf11c48d27594cb9c01fed79d90e5d5a8085c438450111aa7d9fa39c2345b14fc3c2cb34128f86db5eb00bdf8dfe38d61f29a41fe31342e7aaefcb4b122eb5d63c2f5c263c8df8450e9428ffef974d535818d51dc03a7d60c8b2d16c999ae46d73ab40515fe601d9b89b1d09c6d60cd51639a97c1d211e097609ba5e8c319c6fbd21b34a634ec8fb8971c5aae21c70b847a4539cc10dc314ddd8a9629e8a0e51c66c0cb61fd1f7228c01c6769190abe9bac9a3897800050014358594e0fb20dbb458b12aa1346826cc9f7e9c5352b073d62853dafe77c848cb1f'
    await expect(
      verifyRawSignature({
        data: u8a.fromString(message, 'hex'),
        signature: u8a.fromString(signatureHex, 'hex'),
        key: toJwk(publicKeyHex, 'RSA'),
        opts: { signatureAlg: JoseSignatureAlgorithm.PS256 },
      })
    ).resolves.toEqual(true)
  })
})
