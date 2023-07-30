import { generateEbsiPrivateKeyHex } from '../src/functions'

describe('functions: key generator', () => {
  it('Secp256k1 should generate random keys', () => {
    const key1 = generateEbsiPrivateKeyHex()
    const key2 = generateEbsiPrivateKeyHex()
    const key3 = generateEbsiPrivateKeyHex()
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Secp256k1 should result in hex length 64', () => {
    expect(generateEbsiPrivateKeyHex().length).toBe(64)
  })
})
