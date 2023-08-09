import { randomBytes } from '@ethersproject/random'
import { generateKeyPair as generateSigningKeyPair } from '@stablelib/ed25519'
import { IAgentContext, IKey, IKeyManager } from '@veramo/core'

import { JsonWebKey } from 'did-resolver'
import elliptic from 'elliptic'
import * as u8a from 'uint8arrays'
import { ENC_KEY_ALGS, IImportProvidedOrGeneratedKeyArgs, JwkKeyUse, KeyCurve, KeyType, SIG_KEY_ALGS, TKeyType } from './types'
import { generateRSAKeyAsPEM, hexToPEM, PEMToJwk, privateKeyHexFromPEM } from './x509'

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

  let privateKeyHex: string
  if (key) {
    privateKeyHex = key.privateKeyHex ?? key.meta?.x509?.privateKeyHex
    if ((!privateKeyHex || privateKeyHex.trim() === '') && key?.meta?.x509?.privateKeyPEM) {
      // If we do not have a privateKeyHex but do have a PEM
      privateKeyHex = privateKeyHexFromPEM(key.meta.x509.privateKeyPEM)
    }
    if (!privateKeyHex && !key.meta?.x509?.privateKeyPEM) {
      throw new Error(`We need to have a private key in Hex or PEM when importing a key`)
    }
  } else {
    privateKeyHex = await generatePrivateKeyHex(type)
  }

  return context.agent.keyManagerImport({
    ...key,
    kms: args.kms,
    type,
    privateKeyHex,
  })
}

/**
 * Converts hex value to base64url
 * @param value hex value
 * @return Base64Url encoded value
 */
export const hex2base64url = (value: string) => {
  //fixme: Buffer to u8a
  const buffer = Buffer.from(value, 'hex')
  const base64 = buffer.toString('base64')
  const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

  return base64url
}

/**
 * Converts a public key in hex format to a JWK
 * @param publicKeyHex public key in hex
 * @param type The type of the key (Ed25519, Secp256k1/r1)
 * @param opts. Options, like the optional use for the key (sig/enc)
 * @return The JWK
 */
export const toJwk = (publicKeyHex: string, type: TKeyType, opts?: { use?: JwkKeyUse; key?: IKey }): JsonWebKey => {
  const { key } = opts ?? {}
  if (key && key.publicKeyHex !== publicKeyHex) {
    throw Error(`Provided key with id ${key.kid}, has a different public key hex than supplied public key ${publicKeyHex}`)
  }
  switch (type) {
    case 'Ed25519':
      return toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: KeyCurve.Ed25519 })
    case 'X25519':
      return toEd25519OrX25519Jwk(publicKeyHex, { ...opts, crv: KeyCurve.X25519 })
    case 'Secp256k1':
      return toSecp256k1Jwk(publicKeyHex, opts)
    case 'Secp256r1':
      return toSecp256r1Jwk(publicKeyHex, opts)
    case 'RSA':
      return toRSAJwk(publicKeyHex, opts)

    default:
      throw new Error(`not_supported: Key type ${type} not yet supported for this did:jwk implementation`)
  }
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
    if (expectedKeyLength.includes(keyHex.length)) {
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
 * @param publicKeyHex Secp256k1 public key in hex
 * @param use The use for the key
 * @return The JWK
 */
const toSecp256k1Jwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse }): JsonWebKey => {
  assertProperKeyLength(publicKeyHex, 130)
  const { use } = opts ?? {}
  return {
    alg: 'ES256K',
    ...(use !== undefined && { use }),
    kty: KeyType.EC,
    crv: KeyCurve.Secp256k1,
    x: hex2base64url(publicKeyHex.substr(2, 64)),
    y: hex2base64url(publicKeyHex.substr(66, 64)),
  }
}

/**
 * Generates a JWK from a Secp256r1 public key
 * @param publicKeyHex Secp256r1 public key in hex
 * @param use The use for the key
 * @return The JWK
 */
const toSecp256r1Jwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse }): JsonWebKey => {
  const { use } = opts ?? {}
  const publicKey = publicKeyHex
  assertProperKeyLength(publicKey, 66)

  const secp256r1 = new elliptic.ec('p256')
  const key = secp256r1.keyFromPublic(publicKey, 'hex')
  const pubPoint = key.getPublic()
  return {
    alg: 'ES256',
    ...(use !== undefined && { use }),
    kty: KeyType.EC,
    crv: KeyCurve.P_256,
    x: hex2base64url(pubPoint.getX().toString('hex')),
    y: hex2base64url(pubPoint.getY().toString('hex')),
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
): JsonWebKey => {
  assertProperKeyLength(publicKeyHex, 64)
  const { use } = opts ?? {}
  return {
    alg: 'EdDSA',
    ...(use !== undefined && { use }),
    kty: KeyType.OKP,
    crv: opts?.crv ?? KeyCurve.Ed25519,
    x: hex2base64url(publicKeyHex.substr(0, 64)),
  }
}

const toRSAJwk = (publicKeyHex: string, opts?: { use?: JwkKeyUse; key?: IKey }): JsonWebKey => {
  const { key } = opts ?? {}
  // const publicKey = publicKeyHex
  // assertProperKeyLength(publicKey, [2048, 3072, 4096])

  if (key?.meta?.publicKeyJwk) {
    return key.meta.publicKeyJwk as JsonWebKey
  }

  const publicKeyPEM = key?.meta?.publicKeyPEM ?? hexToPEM(publicKeyHex, 'public')
  return PEMToJwk(publicKeyPEM, 'public') as JsonWebKey
}
