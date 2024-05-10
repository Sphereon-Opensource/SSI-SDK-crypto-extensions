import { ebsiDIDSpecInfo, EbsiDidSpecInfo, EbsiEnvironment, EbsiKeyType } from './types'
import { randomBytes } from '@ethersproject/random'
import * as u8a from 'uint8arrays'
import { base58btc } from 'multiformats/bases/base58'
import { IKey } from '@veramo/core'
import { getBytes, SigningKey, sha256, sha512 } from 'ethers'
import { JwkKeyUse, toJwk, JWK } from '@sphereon/ssi-sdk-ext.key-utils'

export const base64url = (input: string): string => u8a.toString(u8a.fromString(input), 'base64url')

export function generateMethodSpecificId(specInfo?: EbsiDidSpecInfo): string {
  const spec = specInfo ?? ebsiDIDSpecInfo.V1
  const length = spec.didLength ?? 16

  const result = new Uint8Array(length + (spec.version ? 1 : 0))
  if (spec.version) {
    result.set([spec.version])
  }
  result.set(randomBytes(length), spec.version ? 1 : 0)
  return base58btc.encode(result)
}

export function generateEbsiPrivateKeyHex(specInfo?: EbsiDidSpecInfo, privateKeyBytes?: Uint8Array): string {
  const spec = specInfo ?? ebsiDIDSpecInfo.V1
  const length = spec.didLength ? 2 * spec.didLength : 32

  if (privateKeyBytes) {
    if (privateKeyBytes.length != length) {
      throw Error(`Invalid private key length supplied (${privateKeyBytes.length}. Expected ${length} for ${spec.type}`)
    }
    return u8a.toString(privateKeyBytes, 'base16')
  }
  return u8a.toString(randomBytes(length), 'base16')
}

/**
 * Returns the public key in the correct format to be used with the did registry v5
 * - in case of Secp256k1 - returns the uncompressed public key as hex string prefixed with 0x04
 * - in case of Secp256r1 - returns the jwk public key as hex string
 * @param {{ key: IKey, type: EbsiKeyType }} args
 *  - key is the cryptographic key containing the public key
 *  - type is the type of the key which can be Secp256k1 or Secp256r1
 *  @returns {string} The properly formatted public key
 *  @throws {Error} If the key type is invalid
 */
export const formatEbsiPublicKey = (args: { key: IKey; type: EbsiKeyType }): string => {
  const { key, type } = args
  switch (type) {
    case 'Secp256k1': {
      const bytes = getBytes('0x' + key.publicKeyHex, 'key')
      return SigningKey.computePublicKey(bytes, false)
    }
    case 'Secp256r1': {
      /*
        Public key as hex string. For an ES256K key, it must be in uncompressed format prefixed with "0x04".
        For other algorithms, it must be the JWK transformed to string and then to hex format.
       */
      const jwk: JsonWebKey = toJwk(key.publicKeyHex, type, { use: JwkKeyUse.Signature, key })
      /*
        Converting JWK to string and then hex is odd and may lead to errors. Implementing
        it like that because it's how EBSI does it. However, it may be a point of pain
        in the future.
       */
      const jwkString = JSON.stringify(jwk, null, 2)
      return u8a.toString(u8a.fromString(jwkString), 'base16')
    }
    default:
      throw new Error(`Invalid key type: ${type}`)
  }
}

export const getUrls = (args: { environment?: EbsiEnvironment; version?: string }): { mutate: string; query: string } => {
  const { environment = 'pilot', version = 'v5' } = args
  const baseUrl = `https://api-${environment}.ebsi.eu/did-registry/${version}`
  return {
    mutate: `${baseUrl}/jsonrpc`,
    query: `${baseUrl}/identifiers`,
  }
}

export const calculateJwkThumbprint = async (args: { jwk: JWK; digestAlgorithm?: 'sha256' | 'sha512' }): Promise<string> => {
  const { jwk, digestAlgorithm = 'sha256' } = args
  let components
  switch (jwk.kty) {
    case 'EC':
      check(jwk.crv, '"crv" (Curve) Parameter')
      check(jwk.x, '"x" (X Coordinate) Parameter')
      check(jwk.y, '"y" (Y Coordinate) Parameter')
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      break
    case 'OKP':
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter')
      check(jwk.x, '"x" (Public Key) Parameter')
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      break
    case 'RSA':
      check(jwk.e, '"e" (Exponent) Parameter')
      check(jwk.n, '"n" (Modulus) Parameter')
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n }
      break
    case 'oct':
      check(jwk.k, '"k" (Key Value) Parameter')
      components = { k: jwk.k, kty: jwk.kty }
      break
    default:
      throw new Error('"kty" (Key Type) Parameter missing or unsupported')
  }
  const data = u8a.fromString(JSON.stringify(components))

  if (digestAlgorithm === 'sha512') {
    return base64url(sha512(data))
  }
  return base64url(sha256(data))
}

const check = (value: unknown, description: string) => {
  if (typeof value !== 'string' || !value) {
    throw new Error(`${description} missing or invalid`)
  }
}
