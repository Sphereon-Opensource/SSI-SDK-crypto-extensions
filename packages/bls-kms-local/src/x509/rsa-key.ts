import { base64ToPEM, JWK } from '@sphereon/ssi-sdk-did-utils'
import crypto from 'isomorphic-webcrypto'
import { HashAlgorithm } from './digest-methods'
import * as u8a from 'uint8arrays'

export type RSASignatureSchemes = 'RSASSA-PKCS1-V1_5' | 'RSA-PSS'

export type RSAEncryptionSchemes = 'RSAES-PKCS-v1_5 ' | 'RSAES-OAEP'

const usage = (jwk: JWK): KeyUsage[] => {
  // "decrypt" | "deriveBits" | "deriveKey" | "encrypt" | "sign" | "unwrapKey" | "verify" | "wrapKey";
  return jwk.d ? ['sign', 'decrypt', 'verify', 'encrypt'] : ['verify', 'encrypt']
}

export const signAlgorithmToSchemeAndHashAlg = (signingAlg: string) => {
  const alg = signingAlg.toUpperCase()
  let scheme: RSAEncryptionSchemes | RSASignatureSchemes
  if (alg.startsWith('RS')) {
    scheme = 'RSASSA-PKCS1-V1_5'
  } else if (alg.startsWith('PS')) {
    scheme = 'RSA-PSS'
  } else {
    throw Error(`Invalid signing algorithm supplied ${signingAlg}`)
  }

  const hashAlgorithm = `SHA-${alg.substring(2)}` as HashAlgorithm
  return { scheme, hashAlgorithm }
}

export const importRSAKey = async (
  jwk: JWK,
  scheme: RSAEncryptionSchemes | RSASignatureSchemes,
  hashAlgorithm?: HashAlgorithm
): Promise<CryptoKey> => {
  const hashName = hashAlgorithm ? hashAlgorithm : jwk.alg ? `SHA-${jwk.alg.substring(2)}` : 'SHA-256'

  const importParams: RsaHashedImportParams = { name: scheme, hash: hashName }
  console.log(`KEY import params: ${JSON.stringify(importParams)}`)
  return await crypto.subtle.importKey('jwk', jwk as JsonWebKey, importParams, false, usage(jwk))
}

export const generateRSAKeyAsPEM = async (
  scheme: RSAEncryptionSchemes | RSASignatureSchemes,
  hashAlgorithm?: HashAlgorithm,
  modulusLength?: number
): Promise<string> => {
  const hashName = hashAlgorithm ? hashAlgorithm : 'SHA-256'

  const params: RsaHashedKeyGenParams = {
    name: scheme,
    hash: hashName,
    modulusLength: modulusLength ? modulusLength : 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  }
  const keyUsage: KeyUsage[] = scheme === 'RSA-PSS' || scheme === 'RSASSA-PKCS1-V1_5' ? ['sign', 'verify'] : ['encrypt', 'decrypt']

  const keypair = await crypto.subtle.generateKey(params, true, keyUsage)
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keypair.privateKey)

  const uint8Array = new Uint8Array(pkcs8)
  return base64ToPEM(u8a.toString(uint8Array, 'base64pad'), 'RSA PRIVATE KEY')
}
