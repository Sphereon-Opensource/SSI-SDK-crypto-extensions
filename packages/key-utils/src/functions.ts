import { randomBytes } from '@ethersproject/random'
import { generateRSAKeyAsPEM, hexToBase64, hexToPEM, PEMToJwk, privateKeyHexFromPEM } from '@sphereon/ssi-sdk-ext.x509-utils'
import { JoseCurve, JoseSignatureAlgorithm, JwkKeyType, JWK, Loggers } from '@sphereon/ssi-types'
import { generateKeyPair as generateSigningKeyPair } from '@stablelib/ed25519'
import { IAgentContext, IKey, IKeyManager, ManagedKeyInfo, MinimalImportableKey } from '@veramo/core'

import { JsonWebKey } from 'did-resolver'
import elliptic from 'elliptic'
import * as u8a from 'uint8arrays'
import { digestMethodParams } from './digest-methods'
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
    alg: JoseSignatureAlgorithm.ES256K,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.EC,
    crv: JoseCurve.secp256k1,
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
    alg: JoseSignatureAlgorithm.ES256,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.EC,
    crv: JoseCurve.P_256,
    x: hexToBase64(pubPoint.getX().toString('hex'), 'base64url'),
    y: hexToBase64(pubPoint.getY().toString('hex'), 'base64url'),
    ...(opts?.isPrivateKey && { d: hexToBase64(keyPair.getPrivate('hex'), 'base64url') }),
  }
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
  return {
    alg: JoseSignatureAlgorithm.EdDSA,
    ...(use !== undefined && { use }),
    kty: JwkKeyType.OKP,
    crv: opts?.crv ?? JoseCurve.Ed25519,
    x: hexToBase64(publicKeyHex, 'base64url'),
  }
}

const toRSAJwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse; key?: IKey | MinimalImportableKey }): JWK => {
  const { key } = opts ?? {}
  // const publicKey = publicKeyHex
  // assertProperKeyLength(publicKey, [2048, 3072, 4096])

  if (key?.meta?.publicKeyJwk) {
    return key.meta.publicKeyJwk as JWK
  }

  const publicKeyPEM = key?.meta?.publicKeyPEM ?? hexToPEM(publicKeyHex, 'public')
  return PEMToJwk(publicKeyPEM, 'public') as JWK
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
    throw new Error('Invalid public key format, an uncompressed raw public key is required as input, not a raw')
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
    case 'Secp256k1':
      return JoseSignatureAlgorithm.ES256K
    default:
      throw new Error(`Key type '${type}' not supported`)
  }
}

// TODO improve this conversion for jwt and jsonld, not a fan of current structure
export const keyTypeFromCryptographicSuite = (args: KeyTypeFromCryptographicSuiteArgs): TKeyType => {
  const { suite } = args
  switch (suite) {
    case 'EdDSA':
    case 'Ed25519Signature2018':
    case 'Ed25519Signature2020':
    case 'JcsEd25519Signature2020':
      return 'Ed25519'
    case 'JsonWebSignature2020':
    case 'ES256':
    case 'ECDSA':
      return 'Secp256r1'
    case 'EcdsaSecp256k1Signature2019':
    case 'ES256K':
      return 'Secp256k1'
    default:
      throw new Error(`Cryptographic suite '${suite}' not supported`)
  }
}

export async function verifySignatureWithSubtle({
  data,
  signature,
  key,
  crypto: cryptoArg,
}: {
  data: Uint8Array
  signature: Uint8Array
  key: JsonWebKey
  crypto?: Crypto
}) {
  let { alg, crv } = key
  if (alg === 'ES256' || !alg) {
    alg = 'ECDSA'
  }

  const subtle = cryptoArg?.subtle ?? crypto.subtle
  const publicKey = await subtle.importKey(
    'jwk',
    key,
    {
      name: alg,
      namedCurve: crv,
    } as EcKeyImportParams,
    true,
    ['verify']
  )

  return subtle.verify(
    {
      name: alg as string,
      hash: 'SHA-256', // fixme; make arg
    },
    publicKey,
    signature,
    data
  )
}
