import {privateKeyHexFromPEM} from "@sphereon/ssi-sdk-ext.x509-utils";
import { generatePrivateKeyHex, Key, padLeft } from '../src'

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
