import { randomBytes } from '@ethersproject/random'
// Do not change these require statements to imports before we change to ESM. Breaks external CJS packages depending on this module
import { bls12_381 } from '@noble/curves/bls12-381'
import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import { p384 } from '@noble/curves/p384'
import { p521 } from '@noble/curves/p521'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { sha384, sha512 } from '@noble/hashes/sha512'
import { generateRSAKeyAsPEM, hexToBase64, hexToPEM, PEMToJwk, privateKeyHexFromPEM } from '@sphereon/ssi-sdk-ext.x509-utils'
import { JoseCurve, JoseSignatureAlgorithm, JWK, JwkKeyType, Loggers } from '@sphereon/ssi-types'
import { generateKeyPair as generateSigningKeyPair } from '@stablelib/ed25519'
import { IAgentContext, IKey, IKeyManager, ManagedKeyInfo, MinimalImportableKey } from '@veramo/core'
import debug from 'debug'

import { JsonWebKey } from 'did-resolver'
import elliptic from 'elliptic'
import * as rsa from 'micro-rsa-dsa-dh/rsa.js'
import * as u8a from 'uint8arrays'
import { digestMethodParams } from './digest-methods'
import { validateJwk } from './jwk-jcs'
import {
  ENC_KEY_ALGS,
  IImportProvidedOrGeneratedKeyArgs,
  JwkKeyUse,
  KeyTypeFromCryptographicSuiteArgs,
  SIG_KEY_ALGS,
  SignatureAlgorithmFromKeyArgs,
  SignatureAlgorithmFromKeyTypeArgs,
  TKeyType,
} from './types'

export const logger = Loggers.DEFAULT.get('sphereon:key-utils')

/**
 * Function that returns the provided KMS name or the default KMS name if none is provided.
 * The default KMS is either explicitly defined during agent construction, or the first KMS available in the system
 * @param context
 * @param kms. Optional KMS to use. If provided will be the returned name. Otherwise the default KMS will be returned
 */
export const getKms = async (context: IAgentContext<any>, kms?: string): Promise<string> => {
  if (kms) {
    return kms
  }
  if (!context.agent.availableMethods().includes('keyManagerGetDefaultKeyManagementSystem')) {
    throw Error('Cannot determine default KMS if not provided and a non Sphereon Key Manager is being used')
  }
  return context.agent.keyManagerGetDefaultKeyManagementSystem()
}

/**
 * Generates a random Private Hex Key for the specified key type
 * @param type The key type
 * @return The private key in Hex form
 */
export const generatePrivateKeyHex = async (type: TKeyType): Promise<string> => {
  switch (type) {
    case 'Ed25519': {
      const keyPairEd25519 = generateSigningKeyPair()
      return u8a.toString(keyPairEd25519.secretKey, 'base16')
    }
    // The Secp256 types use the same method to generate the key
    case 'Secp256r1':
    case 'Secp256k1': {
      const privateBytes = randomBytes(32)
      return u8a.toString(privateBytes, 'base16')
    }
    case 'RSA': {
      const pem = await generateRSAKeyAsPEM('RSA-PSS', 'SHA-256', 2048)
      return privateKeyHexFromPEM(pem)
    }
    default:
      throw Error(`not_supported: Key type ${type} not yet supported for this did:jwk implementation`)
  }
}

const keyMetaAlgorithmsFromKeyType = (type: string | TKeyType) => {
  switch (type) {
    case 'Ed25519':
      return ['Ed25519', 'EdDSA']
    case 'ES256K':
    case 'Secp256k1':
      return ['ES256K', 'ES256K-R', 'eth_signTransaction', 'eth_signTypedData', 'eth_signMessage', 'eth_rawSign']
    case 'Secp256r1':
      return ['ES256']
    case 'X25519':
      return ['ECDH', 'ECDH-ES', 'ECDH-1PU']
    case 'RSA':
      return ['RS256', 'RS512', 'PS256', 'PS512']
  }
  return [type]
}

/**
 * We optionally generate and then import our own keys.
 *
 * @param args The key arguments
 * @param context The Veramo agent context
 * @private
 */
export async function importProvidedOrGeneratedKey(
  args: IImportProvidedOrGeneratedKeyArgs & {
    kms: string
  },
  context: IAgentContext<IKeyManager>
): Promise<IKey> {
  // @ts-ignore
  const type = args.options?.type ?? args.options?.key?.type ?? args.options?.keyType ?? 'Secp256r1'
  const key = args?.options?.key
  // Make sure x509 options are also set on the metadata as that is what the kms will look for
  if (args.options?.x509 && key) {
    key.meta = {
      ...key.meta,
      x509: {
        ...args.options.x509,
        ...key.meta?.x509,
      },
    }
  }

  if (args.options && args.options?.use === JwkKeyUse.Encryption && !ENC_KEY_ALGS.includes(type)) {
    throw new Error(`${type} keys are not valid for encryption`)
  }

  let privateKeyHex: string | undefined = undefined
  if (key) {
    privateKeyHex = key.privateKeyHex ?? key.meta?.x509?.privateKeyHex
    if ((!privateKeyHex || privateKeyHex.trim() === '') && key?.meta?.x509?.privateKeyPEM) {
      // If we do not have a privateKeyHex but do have a PEM
      privateKeyHex = privateKeyHexFromPEM(key.meta.x509.privateKeyPEM)
    }
  }
  if (privateKeyHex) {
    return context.agent.keyManagerImport({
      ...key,
      kms: args.kms,
      type,
      privateKeyHex: privateKeyHex!,
    })
  }

  return context.agent.keyManagerCreate({
    type,
    kms: args.kms,
    meta: {
      ...key?.meta,
      algorithms: keyMetaAlgorithmsFromKeyType(type),
      keyAlias: args.alias,
    },
  })
}

export const calculateJwkThumbprintForKey = (args: {
  key: IKey | MinimalImportableKey | ManagedKeyInfo
  digestAlgorithm?: 'sha256' | 'sha512'
}): string => {
  const { key } = args

  const jwk = key.publicKeyHex
    ? toJwk(key.publicKeyHex, key.type, { key: key, isPrivateKey: false })
    : 'privateKeyHex' in key && key.privateKeyHex
    ? toJwk(key.privateKeyHex, key.type, { isPrivateKey: true })
    : undefined
  if (!jwk) {
    throw Error(`Could not determine jwk from key ${key.kid}`)
  }
  return calculateJwkThumbprint({ jwk, digestAlgorithm: args.digestAlgorithm })
}

const assertJwkClaimPresent = (value: unknown, description: string) => {
  if (typeof value !== 'string' || !value) {
    throw new Error(`${description} missing or invalid`)
  }
}
export const toBase64url = (input: string): string => u8a.toString(u8a.fromString(input), 'base64url')

/**
 * Calculate the JWK thumbprint
 * @param args
 */
export const calculateJwkThumbprint = (args: { jwk: JWK; digestAlgorithm?: 'sha256' | 'sha512' }): string => {
  const { digestAlgorithm = 'sha256' } = args
  const jwk = sanatizedJwk(args.jwk)
  let components
  switch (jwk.kty) {
    case 'EC':
      assertJwkClaimPresent(jwk.crv, '"crv" (Curve) Parameter')
      assertJwkClaimPresent(jwk.x, '"x" (X Coordinate) Parameter')
      assertJwkClaimPresent(jwk.y, '"y" (Y Coordinate) Parameter')
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      break
    case 'OKP':
      assertJwkClaimPresent(jwk.crv, '"crv" (Subtype of Key Pair) Parameter')
      assertJwkClaimPresent(jwk.x, '"x" (Public Key) Parameter')
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      break
    case 'RSA':
      assertJwkClaimPresent(jwk.e, '"e" (Exponent) Parameter')
      assertJwkClaimPresent(jwk.n, '"n" (Modulus) Parameter')
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n }
      break
    case 'oct':
      assertJwkClaimPresent(jwk.k, '"k" (Key Value) Parameter')
      components = { k: jwk.k, kty: jwk.kty }
      break
    default:
      throw new Error('"kty" (Key Type) Parameter missing or unsupported')
  }
  const data = JSON.stringify(components)

  return digestAlgorithm === 'sha512'
    ? digestMethodParams('SHA-512').digestMethod(data, 'base64url')
    : digestMethodParams('SHA-256').digestMethod(data, 'base64url')
}

export const toJwkFromKey = (
  key: IKey | MinimalImportableKey | ManagedKeyInfo,
  opts?: {
    use?: JwkKeyUse
    noKidThumbprint?: boolean
  }
): JWK => {
  const isPrivateKey = 'privateKeyHex' in key
  return toJwk(key.publicKeyHex!, key.type, { ...opts, key, isPrivateKey })
}

/**
 * Converts a public key in hex format to a JWK
 * @param publicKeyHex public key in hex
 * @param type The type of the key (Ed25519, Secp256k1/r1)
 * @param opts. Options, like the optional use for the key (sig/enc)
 * @return The JWK
 */
export const toJwk = (
  publicKeyHex: string,
  type: TKeyType,
  opts?: { use?: JwkKeyUse; key?: IKey | MinimalImportableKey; isPrivateKey?: boolean; noKidThumbprint?: boolean }
): JWK => {
  const { key, noKidThumbprint = false } = opts ?? {}
  if (key && key.publicKeyHex !== publicKeyHex && opts?.isPrivateKey !== true) {
    throw Error(`Provided key with id ${key.kid}, has a different public key hex ${key.publicKeyHex} than supplied public key ${publicKeyHex}`)
  }
  let jwk: JWK
  switch (type) {
    case 'Ed25519':
      jwk = toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: JoseCurve.Ed25519 })
      break
    case 'X25519':
      jwk = toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: JoseCurve.X25519 })
      break
    case 'Secp256k1':
      jwk = toSecp256k1Jwk(publicKeyHex, opts)
      break
    case 'Secp256r1':
      jwk = toSecp256r1Jwk(publicKeyHex, opts)
      break
    case 'RSA':
      jwk = toRSAJwk(publicKeyHex, opts)
      break
    default:
      throw new Error(`not_supported: Key type ${type} not yet supported for this did:jwk implementation`)
  }
  if (!jwk.kid && !noKidThumbprint) {
    jwk['kid'] = calculateJwkThumbprint({ jwk })
  }
  return sanatizedJwk(jwk)
}

/**
 * Convert a JWK to a raw hex key.
 * Currently supports `RSA` and `EC` keys. Extendable for other key types.
 * @param jwk - The JSON Web Key object.
 * @returns A string representing the key in raw hexadecimal format.
 */
export const jwkToRawHexKey = async (jwk: JWK): Promise<string> => {
  // TODO: Probably makes sense to have an option to do the same for private keys
  jwk = sanatizedJwk(jwk)
  if (jwk.kty === 'RSA') {
    return rsaJwkToRawHexKey(jwk)
  } else if (jwk.kty === 'EC') {
    return ecJwkToRawHexKey(jwk)
  } else if (jwk.kty === 'OKP') {
    return okpJwkToRawHexKey(jwk)
  } else if (jwk.kty === 'oct') {
    return octJwkToRawHexKey(jwk)
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`)
  }
}

/**
 * Convert an RSA JWK to a raw hex key.
 * @param jwk - The RSA JWK object.
 * @returns A string representing the RSA key in raw hexadecimal format.
 */
function rsaJwkToRawHexKey(jwk: JsonWebKey): string {
  jwk = sanatizedJwk(jwk)
  if (!jwk.n || !jwk.e) {
    throw new Error("RSA JWK must contain 'n' and 'e' properties.")
  }

  // We are converting from base64 to base64url to be sure. The spec uses base64url, but in the wild we sometimes encounter a base64 string
  const modulus = u8a.fromString(jwk.n.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url') // 'n' is the modulus
  const exponent = u8a.fromString(jwk.e.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url') // 'e' is the exponent

  return u8a.toString(modulus, 'hex') + u8a.toString(exponent, 'hex')
}

/**
 * Convert an EC JWK to a raw hex key.
 * @param jwk - The EC JWK object.
 * @returns A string representing the EC key in raw hexadecimal format.
 */
function ecJwkToRawHexKey(jwk: JsonWebKey): string {
  jwk = sanatizedJwk(jwk)
  if (!jwk.x || !jwk.y) {
    throw new Error("EC JWK must contain 'x' and 'y' properties.")
  }

  // We are converting from base64 to base64url to be sure. The spec uses base64url, but in the wild we sometimes encounter a base64 string
  const x = u8a.fromString(jwk.x.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url')
  const y = u8a.fromString(jwk.y.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url')

  return '04' + u8a.toString(x, 'hex') + u8a.toString(y, 'hex')
}

/**
 * Convert an EC JWK to a raw hex key.
 * @param jwk - The EC JWK object.
 * @returns A string representing the EC key in raw hexadecimal format.
 */
function okpJwkToRawHexKey(jwk: JsonWebKey): string {
  jwk = sanatizedJwk(jwk)
  if (!jwk.x) {
    throw new Error("OKP JWK must contain 'x' property.")
  }

  // We are converting from base64 to base64url to be sure. The spec uses base64url, but in the wild we sometimes encounter a base64 string
  const x = u8a.fromString(jwk.x.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url')

  return u8a.toString(x, 'hex')
}

/**
 * Convert an octet JWK to a raw hex key.
 * @param jwk - The octet JWK object.
 * @returns A string representing the octet key in raw hexadecimal format.
 */
function octJwkToRawHexKey(jwk: JsonWebKey): string {
  jwk = sanatizedJwk(jwk)
  if (!jwk.k) {
    throw new Error("Octet JWK must contain 'k' property.")
  }

  // We are converting from base64 to base64url to be sure. The spec uses base64url, but in the wild we sometimes encounter a base64 string
  const key = u8a.fromString(jwk.k.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url')

  return u8a.toString(key, 'hex')
}

/**
 * Determines the use param based upon the key/signature type or supplied use value.
 *
 * @param type The key type
 * @param suppliedUse A supplied use. Will be used in case it is present
 */
export const jwkDetermineUse = (type: TKeyType, suppliedUse?: JwkKeyUse): JwkKeyUse | undefined => {
  return suppliedUse
    ? suppliedUse
    : SIG_KEY_ALGS.includes(type)
    ? JwkKeyUse.Signature
    : ENC_KEY_ALGS.includes(type)
    ? JwkKeyUse.Encryption
    : undefined
}

/**
 * Assert the key has a proper length
 *
 * @param keyHex Input key
 * @param expectedKeyLength Expected key length(s)
 */
const assertProperKeyLength = (keyHex: string, expectedKeyLength: number | number[]) => {
  if (Array.isArray(expectedKeyLength)) {
    if (!expectedKeyLength.includes(keyHex.length)) {
      throw Error(
        `Invalid key length. Needs to be a hex string with length from ${JSON.stringify(expectedKeyLength)} instead of ${
          keyHex.length
        }. Input: ${keyHex}`
      )
    }
  } else if (keyHex.length !== expectedKeyLength) {
    throw Error(`Invalid key length. Needs to be a hex string with length ${expectedKeyLength} instead of ${keyHex.length}. Input: ${keyHex}`)
  }
}

/**
 * Generates a JWK from a Secp256k1 public key
 * @param keyHex Secp256k1 public or private key in hex
 * @param use The use for the key
 * @return The JWK
 */
const toSecp256k1Jwk = (keyHex: string, opts?: { use?: JwkKeyUse; isPrivateKey?: boolean }): JWK => {
  const { use } = opts ?? {}
  logger.debug(`toSecp256k1Jwk keyHex: ${keyHex}, length: ${keyHex.length}`)
  if (opts?.isPrivateKey) {
    assertProperKeyLength(keyHex, [64])
  } else {
    assertProperKeyLength(keyHex, [66, 130])
  }

  const secp256k1 = new elliptic.ec('secp256k1')
  const keyBytes = u8a.fromString(keyHex, 'base16')
  const keyPair = opts?.isPrivateKey ? secp256k1.keyFromPrivate(keyBytes) : secp256k1.keyFromPublic(keyBytes)
  const pubPoint = keyPair.getPublic()

  return sanatizedJwk({
    alg: JoseSignatureAlgorithm.ES256K,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.EC,
    crv: JoseCurve.secp256k1,
    x: hexToBase64(pubPoint.getX().toString('hex'), 'base64url'),
    y: hexToBase64(pubPoint.getY().toString('hex'), 'base64url'),
    ...(opts?.isPrivateKey && { d: hexToBase64(keyPair.getPrivate('hex'), 'base64url') }),
  })
}

/**
 * Generates a JWK from a Secp256r1 public key
 * @param keyHex Secp256r1 public key in hex
 * @param use The use for the key
 * @return The JWK
 */
const toSecp256r1Jwk = (keyHex: string, opts?: { use?: JwkKeyUse; isPrivateKey?: boolean }): JWK => {
  const { use } = opts ?? {}
  logger.debug(`toSecp256r1Jwk keyHex: ${keyHex}, length: ${keyHex.length}`)
  if (opts?.isPrivateKey) {
    assertProperKeyLength(keyHex, [64])
  } else {
    assertProperKeyLength(keyHex, [66, 130])
  }

  const secp256r1 = new elliptic.ec('p256')
  const keyBytes = u8a.fromString(keyHex, 'base16')
  logger.debug(`keyBytes length: ${keyBytes}`)
  const keyPair = opts?.isPrivateKey ? secp256r1.keyFromPrivate(keyBytes) : secp256r1.keyFromPublic(keyBytes)
  const pubPoint = keyPair.getPublic()
  return sanatizedJwk({
    alg: JoseSignatureAlgorithm.ES256,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.EC,
    crv: JoseCurve.P_256,
    x: hexToBase64(pubPoint.getX().toString('hex'), 'base64url'),
    y: hexToBase64(pubPoint.getY().toString('hex'), 'base64url'),
    ...(opts?.isPrivateKey && { d: hexToBase64(keyPair.getPrivate('hex'), 'base64url') }),
  })
}

/**
 * Generates a JWK from an Ed25519/X25519 public key
 * @param publicKeyHex Ed25519/X25519 public key in hex
 * @param opts
 * @return The JWK
 */
const toEd25519OrX25519Jwk = (
  publicKeyHex: string,
  opts: {
    use?: JwkKeyUse
    crv: JoseCurve.Ed25519 | JoseCurve.X25519
  }
): JWK => {
  assertProperKeyLength(publicKeyHex, 64)
  const { use } = opts ?? {}
  return sanatizedJwk({
    alg: JoseSignatureAlgorithm.EdDSA,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.OKP,
    crv: opts?.crv ?? JoseCurve.Ed25519,
    x: hexToBase64(publicKeyHex, 'base64url'),
  })
}

const toRSAJwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse; key?: IKey | MinimalImportableKey }): JWK => {
  const meta = opts?.key?.meta
  if (meta?.publicKeyJwk || meta?.publicKeyPEM) {
    if (meta?.publicKeyJwk) {
      return meta.publicKeyJwk as JWK
    }
    const publicKeyPEM = meta?.publicKeyPEM ?? hexToPEM(publicKeyHex, 'public')
    return PEMToJwk(publicKeyPEM, 'public') as JWK
  }

  // exponent (e) is 5 chars long, rest is modulus (n)
  // const publicKey = publicKeyHex
  // assertProperKeyLength(publicKey, [2048, 3072, 4096])
  const exponent = publicKeyHex.slice(-5)
  const modulus = publicKeyHex.slice(0, -5)
  // const modulusBitLength  = (modulus.length / 2) * 8

  // const alg = modulusBitLength === 2048 ? JoseSignatureAlgorithm.RS256 : modulusBitLength === 3072 ? JoseSignatureAlgorithm.RS384 : modulusBitLength === 4096 ? JoseSignatureAlgorithm.RS512 : undefined
  return sanatizedJwk({
    kty: 'RSA',
    n: hexToBase64(modulus, 'base64url'),
    e: hexToBase64(exponent, 'base64url'),
    // ...(alg && { alg }),
  })
}

export const padLeft = (args: { data: string; size?: number; padString?: string }): string => {
  const { data } = args
  const size = args.size ?? 32
  const padString = args.padString ?? '0'
  if (data.length >= size) {
    return data
  }

  if (padString && padString.length === 0) {
    throw Error(`Pad string needs to have at least a length of 1`)
  }
  const length = padString.length
  return padString.repeat((size - data.length) / length) + data
}

enum OIDType {
  Secp256k1,
  Secp256r1,
  Ed25519,
}

const OID: Record<OIDType, Uint8Array> = {
  [OIDType.Secp256k1]: new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
  [OIDType.Secp256r1]: new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
  [OIDType.Ed25519]: new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]),
}

const compareUint8Arrays = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

const findSubarray = (haystack: Uint8Array, needle: Uint8Array): number => {
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    if (compareUint8Arrays(haystack.subarray(i, i + needle.length), needle)) {
      return i
    }
  }
  return -1
}

const getTargetOID = (keyType: TKeyType) => {
  switch (keyType) {
    case 'Secp256k1':
      return OID[OIDType.Secp256k1]
    case 'Secp256r1':
      return OID[OIDType.Secp256r1]
    case 'Ed25519':
      return OID[OIDType.Ed25519]
    default:
      throw new Error(`Unsupported key type: ${keyType}`)
  }
}

export const isAsn1Der = (key: Uint8Array): boolean => key[0] === 0x30

export const asn1DerToRawPublicKey = (derKey: Uint8Array, keyType: TKeyType): Uint8Array => {
  if (!isAsn1Der(derKey)) {
    throw new Error('Invalid DER encoding: Expected to start with sequence tag')
  }

  let index = 2
  if (derKey[1] & 0x80) {
    const lengthBytesCount = derKey[1] & 0x7f
    index += lengthBytesCount
  }
  const targetOid = getTargetOID(keyType)
  const oidIndex = findSubarray(derKey, targetOid)
  if (oidIndex === -1) {
    throw new Error(`OID for ${keyType} not found in DER encoding`)
  }

  index = oidIndex + targetOid.length

  while (index < derKey.length && derKey[index] !== 0x03) {
    index++
  }

  if (index >= derKey.length) {
    throw new Error('Invalid DER encoding: Bit string not found')
  }

  // Skip the bit string tag (0x03) and length byte
  index += 2

  // Skip the unused bits count byte
  index++

  return derKey.slice(index)
}

export const isRawCompressedPublicKey = (key: Uint8Array): boolean => key.length === 33 && (key[0] === 0x02 || key[0] === 0x03)

export const toRawCompressedHexPublicKey = (rawPublicKey: Uint8Array, keyType: TKeyType): string => {
  if (isRawCompressedPublicKey(rawPublicKey)) {
    return hexStringFromUint8Array(rawPublicKey)
  }

  if (keyType === 'Secp256k1' || keyType === 'Secp256r1') {
    if (rawPublicKey[0] === 0x04 && rawPublicKey.length === 65) {
      const xCoordinate = rawPublicKey.slice(1, 33)
      const yCoordinate = rawPublicKey.slice(33)
      const prefix = new Uint8Array([yCoordinate[31] % 2 === 0 ? 0x02 : 0x03])
      const resultKey = hexStringFromUint8Array(new Uint8Array([...prefix, ...xCoordinate]))
      logger.debug(`converted public key ${hexStringFromUint8Array(rawPublicKey)} to ${resultKey}`)
      return resultKey
    }
    return u8a.toString(rawPublicKey, 'base16')
  } else if (keyType === 'Ed25519') {
    // Ed25519 keys are always in compressed form
    return u8a.toString(rawPublicKey, 'base16')
  }

  throw new Error(`Unsupported key type: ${keyType}`)
}

export const hexStringFromUint8Array = (value: Uint8Array): string => u8a.toString(value, 'base16')

export const signatureAlgorithmFromKey = async (args: SignatureAlgorithmFromKeyArgs): Promise<JoseSignatureAlgorithm> => {
  const { key } = args
  return signatureAlgorithmFromKeyType({ type: key.type })
}

export const signatureAlgorithmFromKeyType = (args: SignatureAlgorithmFromKeyTypeArgs): JoseSignatureAlgorithm => {
  const { type } = args
  switch (type) {
    case 'Ed25519':
    case 'X25519':
      return JoseSignatureAlgorithm.EdDSA
    case 'Secp256r1':
      return JoseSignatureAlgorithm.ES256
    case 'Secp384r1':
      return JoseSignatureAlgorithm.ES384
    case 'Secp521r1':
      return JoseSignatureAlgorithm.ES512
    case 'Secp256k1':
      return JoseSignatureAlgorithm.ES256K
    default:
      throw new Error(`Key type '${type}' not supported`)
  }
}

// TODO improve this conversion for jwt and jsonld, not a fan of current structure
export const keyTypeFromCryptographicSuite = (args: KeyTypeFromCryptographicSuiteArgs): TKeyType => {
  const { crv, kty, alg } = args

  switch (alg) {
    case 'RSASSA-PSS':
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return 'RSA'
  }

  switch (crv) {
    case 'EdDSA':
    case 'Ed25519':
    case 'Ed25519Signature2018':
    case 'Ed25519Signature2020':
    case 'JcsEd25519Signature2020':
      return 'Ed25519'
    case 'JsonWebSignature2020':
    case 'ES256':
    case 'ECDSA':
    case 'P-256':
      return 'Secp256r1'
    case 'ES384':
    case 'P-384':
      return 'Secp384r1'
    case 'ES512':
    case 'P-521':
      return 'Secp521r1'
    case 'EcdsaSecp256k1Signature2019':
    case 'secp256k1':
    case 'ES256K':
      return 'Secp256k1'
  }
  if (kty) {
    return kty as TKeyType
  }

  throw new Error(`Cryptographic suite '${crv}' not supported`)
}

export function removeNulls<T>(obj: T | any) {
  Object.keys(obj).forEach((key) => {
    if (obj[key] && typeof obj[key] === 'object') removeNulls(obj[key])
    else if (obj[key] == null) delete obj[key]
  })
  return obj
}

export const globalCrypto = (setGlobal: boolean, suppliedCrypto?: Crypto): Crypto => {
  let webcrypto: Crypto
  if (typeof suppliedCrypto !== 'undefined') {
    webcrypto = suppliedCrypto
  } else if (typeof crypto !== 'undefined') {
    webcrypto = crypto
  } else if (typeof global.crypto !== 'undefined') {
    webcrypto = global.crypto
  } else if (typeof global.window?.crypto?.subtle !== 'undefined') {
    webcrypto = global.window.crypto
  } else {
    webcrypto = require('crypto') as Crypto
  }
  if (setGlobal) {
    global.crypto = webcrypto
  }

  return webcrypto
}

export const sanatizedJwk = (inputJwk: JWK | JsonWebKey): JWK => {
  const jwk = {
    ...inputJwk,
    ...(inputJwk.x && { x: base64ToBase64Url(inputJwk.x as string) }),
    ...(inputJwk.y && { y: base64ToBase64Url(inputJwk.y as string) }),
    ...(inputJwk.d && { d: base64ToBase64Url(inputJwk.d as string) }),
    ...(inputJwk.n && { n: base64ToBase64Url(inputJwk.n as string) }),
    ...(inputJwk.e && { e: base64ToBase64Url(inputJwk.e as string) }),
    ...(inputJwk.k && { k: base64ToBase64Url(inputJwk.k as string) }),
  } as JWK

  return removeNulls(jwk)
}

const base64ToBase64Url = (input: string): string => {
  return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 *
 */
export async function verifyRawSignature({
  data,
  signature,
  key: inputKey,
  opts,
}: {
  data: Uint8Array
  signature: Uint8Array
  key: JWK
  opts?: {
    signatureAlg?: JoseSignatureAlgorithm
  }
}) {
  /**
   * Converts a Base64URL-encoded JWK property to a BigInt.
   * @param jwkProp - The Base64URL-encoded string.
   * @returns The BigInt representation of the decoded value.
   */
  function jwkPropertyToBigInt(jwkProp: string): bigint {
    // Decode Base64URL to Uint8Array
    const byteArray = u8a.fromString(jwkProp, 'base64url')

    // Convert Uint8Array to hexadecimal string and then to BigInt
    const hex = u8a.toString(byteArray, 'hex')
    return BigInt(`0x${hex}`)
  }

  try {
    debug(`verifyRawSignature for: ${inputKey}`)
    const jwk = sanatizedJwk(inputKey)
    validateJwk(jwk, { crvOptional: true })
    const keyType = keyTypeFromCryptographicSuite({ crv: jwk.crv, kty: jwk.kty, alg: jwk.alg })
    const publicKeyHex = await jwkToRawHexKey(jwk)

    // TODO: We really should look at the signature alg first if provided! From key type should be the last resort
    switch (keyType) {
      case 'Secp256k1':
        return secp256k1.verify(signature, data, publicKeyHex, { format: 'compact', prehash: true })
      case 'Secp256r1':
        return p256.verify(signature, data, publicKeyHex, { format: 'compact', prehash: true })
      case 'Secp384r1':
        return p384.verify(signature, data, publicKeyHex, { format: 'compact', prehash: true })
      case 'Secp521r1':
        return p521.verify(signature, data, publicKeyHex, { format: 'compact', prehash: true })
      case 'Ed25519':
        return ed25519.verify(signature, data, u8a.fromString(publicKeyHex, 'hex'))
      case 'Bls12381G1':
      case 'Bls12381G2':
        return bls12_381.verify(signature, data, u8a.fromString(publicKeyHex, 'hex'))
      case 'RSA': {
        const signatureAlgorithm = opts?.signatureAlg ?? JoseSignatureAlgorithm.PS256
        const hashAlg =
          signatureAlgorithm === (JoseSignatureAlgorithm.RS512 || JoseSignatureAlgorithm.PS512)
            ? sha512
            : signatureAlgorithm === (JoseSignatureAlgorithm.RS384 || JoseSignatureAlgorithm.PS384)
            ? sha384
            : sha256
        switch (signatureAlgorithm) {
          case JoseSignatureAlgorithm.RS256:
            return rsa.PKCS1_SHA256.verify(
              {
                n: jwkPropertyToBigInt(jwk.n!),
                e: jwkPropertyToBigInt(jwk.e!),
              },
              data,
              signature
            )
          case JoseSignatureAlgorithm.RS384:
            return rsa.PKCS1_SHA384.verify(
              {
                n: jwkPropertyToBigInt(jwk.n!),
                e: jwkPropertyToBigInt(jwk.e!),
              },
              data,
              signature
            )
          case JoseSignatureAlgorithm.RS512:
            return rsa.PKCS1_SHA512.verify(
              {
                n: jwkPropertyToBigInt(jwk.n!),
                e: jwkPropertyToBigInt(jwk.e!),
              },
              data,
              signature
            )
          case JoseSignatureAlgorithm.PS256:
          case JoseSignatureAlgorithm.PS384:
          case JoseSignatureAlgorithm.PS512:
            return rsa.PSS(hashAlg, rsa.mgf1(hashAlg)).verify(
              {
                n: jwkPropertyToBigInt(jwk.n!),
                e: jwkPropertyToBigInt(jwk.e!),
              },
              data,
              signature
            )
        }
      }
    }

    throw Error(`Unsupported key type for signature validation: ${keyType}`)
  } catch (error: any) {
    logger.error(`Error: ${error}`)
    throw error
  }
}
