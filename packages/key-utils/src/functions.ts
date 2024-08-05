import { randomBytes } from '@ethersproject/random'
import { generateKeyPair as generateSigningKeyPair } from '@stablelib/ed25519'
import { IAgentContext, IKey, IKeyManager, ManagedKeyInfo, MinimalImportableKey } from '@veramo/core'

import { JsonWebKey } from 'did-resolver'
import elliptic from 'elliptic'
import * as u8a from 'uint8arrays'
import { digestMethodParams } from './digest-methods'
import { ENC_KEY_ALGS, IImportProvidedOrGeneratedKeyArgs, JWK, JwkKeyUse, KeyCurve, KeyType, SIG_KEY_ALGS, TKeyType } from './types'
import { generateRSAKeyAsPEM, hexToBase64, hexToPEM, PEMToJwk, privateKeyHexFromPEM } from './x509'
import { Loggers } from '@sphereon/ssi-types'

export const logger = Loggers.DEFAULT.get('sphereon:key-utils')

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

const algorithmsFromKeyType = (type: string): string[] => [type] // TODO BEFORE PR, is correct?

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
      algorithms: algorithmsFromKeyType(type),
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
  const { jwk, digestAlgorithm = 'sha256' } = args
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
      jwk = toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: KeyCurve.Ed25519 })
      break
    case 'X25519':
      jwk = toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: KeyCurve.X25519 })
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
  return jwk
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

  return {
    alg: 'ES256K',
    ...(use !== undefined && { use }),
    kty: KeyType.EC,
    crv: KeyCurve.Secp256k1,
    x: hexToBase64(pubPoint.getX().toString('hex'), 'base64url'),
    y: hexToBase64(pubPoint.getY().toString('hex'), 'base64url'),
    ...(opts?.isPrivateKey && { d: hexToBase64(keyPair.getPrivate('hex'), 'base64url') }),
  }
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
  return {
    alg: 'ES256',
    ...(use !== undefined && { use }),
    kty: KeyType.EC,
    crv: KeyCurve.P_256,
    x: hexToBase64(pubPoint.getX().toString('hex'), 'base64url'),
    y: hexToBase64(pubPoint.getY().toString('hex'), 'base64url'),
    ...(opts?.isPrivateKey && { d: hexToBase64(keyPair.getPrivate('hex'), 'base64url') }),
  }
}

/**
 * Generates a JWK from an Ed25519/X25519 public key
 * @param publicKeyHex Ed25519/X25519 public key in hex
 * @param use The use for the key
 * @return The JWK
 */
const toEd25519OrX25519Jwk = (
  publicKeyHex: string,
  opts: {
    use?: JwkKeyUse
    crv: KeyCurve.Ed25519 | KeyCurve.X25519
  }
): JWK => {
  assertProperKeyLength(publicKeyHex, 64)
  const { use } = opts ?? {}
  return {
    alg: 'EdDSA',
    ...(use !== undefined && { use }),
    kty: KeyType.OKP,
    crv: opts?.crv ?? KeyCurve.Ed25519,
    x: hexToBase64(publicKeyHex, 'base64url'),
  }
}

const toRSAJwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse; key?: IKey | MinimalImportableKey }): JWK => {
  const { key } = opts ?? {}
  // const publicKey = publicKeyHex
  // assertProperKeyLength(publicKey, [2048, 3072, 4096])

  if (key?.meta?.publicKeyJwk) {
    return key.meta.publicKeyJwk as JsonWebKey
  }

  const publicKeyPEM = key?.meta?.publicKeyPEM ?? hexToPEM(publicKeyHex, 'public')
  return PEMToJwk(publicKeyPEM, 'public') as JsonWebKey
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
  Ed25519
}

const OID: Record<OIDType, Uint8Array> = {
  [OIDType.Secp256k1]: new Uint8Array([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
  [OIDType.Secp256r1]: new Uint8Array([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
  [OIDType.Ed25519]: new Uint8Array([0x06, 0x03, 0x2B, 0x65, 0x70])
}

function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
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

function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    if (compareUint8Arrays(haystack.subarray(i, i + needle.length), needle)) {
      return i
    }
  }
  return -1
}

function getTargetOID(keyType: TKeyType) {
  switch (keyType) {
    case 'Secp256k1':
      return  OID[OIDType.Secp256k1]
    case 'Secp256r1':
      return  OID[OIDType.Secp256r1]
    case 'Ed25519':
      return OID[OIDType.Ed25519]
    default:
      throw new Error(`Unsupported key type: ${keyType}`)
  }
}
export function rawPublicKeyHexFromAsn1Der(
  derKey: Uint8Array,
  keyType: TKeyType,
  compressed: boolean = true
): string {
  if (derKey[0] !== 0x30) {
    throw new Error('Invalid DER encoding: Expected to start with sequence tag')
  }

  let index = 2
  if (derKey[1] & 0x80) {
    const lengthBytesCount = derKey[1] & 0x7F
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

  const rawPublicKeyBytes = derKey.slice(index)

  if (keyType === 'Secp256k1' || keyType === 'Secp256r1') {
    if (rawPublicKeyBytes[0] === 0x04 && rawPublicKeyBytes.length === 65) {
      const xCoordinate = rawPublicKeyBytes.slice(1, 33)
      const yCoordinate = rawPublicKeyBytes.slice(33)
      if (compressed) {
        const prefix = new Uint8Array([yCoordinate[31] % 2 === 0 ? 0x02 : 0x03])
        return u8a.toString(new Uint8Array([...prefix, ...xCoordinate]), 'base16')
      } else {
        return u8a.toString(rawPublicKeyBytes, 'base16')
      }
    } else {
      throw new Error('Invalid uncompressed public key format.')
    }
  } else if (keyType === 'Ed25519') {
    return u8a.toString(rawPublicKeyBytes, 'base16')
  }

  throw new Error(`Invalid key length or unsupported key type. Got ${rawPublicKeyBytes.length} bytes.`)
}
