import { ebsiDIDSpecInfo, EbsiDidSpecInfo } from './types'
import { randomBytes } from '@ethersproject/random'
import * as u8a from 'uint8arrays'
import { base58btc } from 'multiformats/bases/base58'

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
