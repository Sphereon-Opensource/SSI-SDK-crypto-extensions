import {ebsiDIDSpecInfo, EbsiDidSpecInfo, EbsiEnvironment, EbsiKeyType} from './types'
import { randomBytes } from '@ethersproject/random'
import * as u8a from 'uint8arrays'
import { base58btc } from 'multiformats/bases/base58'
import { IKey } from '@veramo/core'
import { getBytes, SigningKey } from 'ethers'
import { JwkKeyUse, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'

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
      const jwk: JsonWebKey = toJwk(key.publicKeyHex, type, { use: JwkKeyUse.Signature, key })
      const jwkString = JSON.stringify(jwk, null, 2)
      return u8a.toString(u8a.fromString(jwkString), 'base16')
    }
    default:
      throw new Error(`Invalid key type: ${type}`)
  }
}

export const getDidRegistryRPCUrl = (args: { environment?: EbsiEnvironment, version?: string }) => {
  const { environment = 'pilot', version = 'v5' } = args
  return `https://api-${environment}.ebsi.eu/did-registry/${version}/jsonrpc`
}
