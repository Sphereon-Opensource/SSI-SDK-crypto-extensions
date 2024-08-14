import { IKey, MinimalImportableKey } from '@veramo/core'

export const JWK_JCS_PUB_NAME = 'jwk_jcs-pub' as const
export const JWK_JCS_PUB_PREFIX = 0xeb51

export type TKeyType = 'Ed25519' | 'Secp256k1' | 'Secp256r1' | 'X25519' | 'Bls12381G1' | 'Bls12381G2' | 'RSA'

export enum Key {
  Ed25519 = 'Ed25519',
  Secp256k1 = 'Secp256k1',
  Secp256r1 = 'Secp256r1',
}

export enum JwkKeyUse {
  Encryption = 'enc',
  Signature = 'sig',
}

export enum KeyCurve {
  Secp256k1 = 'secp256k1',
  P_256 = 'P-256',
  Ed25519 = 'Ed25519',
  X25519 = 'X25519',
}

export enum KeyType {
  EC = 'EC',
  OKP = 'OKP',
  RSA = 'RSA',
}

export const SIG_KEY_ALGS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'ES256K', 'Ed25519', 'Secp256k1', 'Secp256r1', 'Bls12381G1', 'Bls12381G2']
export const ENC_KEY_ALGS = ['X25519', 'ECDH_ES_A256KW', 'RSA_OAEP_256']

export interface JWK {
  kty: string
  alg?: string
  crv?: string
  d?: string
  dp?: string
  dq?: string
  e?: string
  ext?: boolean
  k?: string
  key_ops?: string[]
  kid?: string
  n?: string
  oth?: Array<{
    d?: string
    r?: string
    t?: string
  }>
  p?: string
  q?: string
  qi?: string
  use?: string
  x?: string
  y?: string
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c?: string[]
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t?: string
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256'?: string
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u?: string
  [propName: string]: unknown
}

export type KeyVisibility = 'public' | 'private'

export interface X509Opts {
  cn?: string // The certificate Common Name. Will be used as the KID for the private key. Uses alias if not provided.
  privateKeyPEM?: string // Optional as you also need to provide it in hex format, but advisable to use it
  certificatePEM?: string // Optional, as long as the certificate then is part of the certificateChainPEM
  certificateChainURL?: string // Certificate chain URL. If used this is where the certificateChainPEM will be hosted/found.
  certificateChainPEM?: string // Base64 (not url!) encoded DER certificate chain. Please provide even if certificateChainURL is used!
}

export interface IImportProvidedOrGeneratedKeyArgs {
  kms?: string
  alias?: string
  options?: IKeyOpts
}
export interface IKeyOpts {
  key?: Partial<MinimalImportableKey> // Optional key to import with only privateKeyHex mandatory. If not specified a key with random kid will be created
  type?: TKeyType // The key type. Defaults to Secp256k1
  use?: JwkKeyUse // The key use
  x509?: X509Opts
}
/*
// Needed to make a single property required
type WithRequiredProperty<Type, Key extends keyof Type> = Type & {
  [Property in Key]-?: Type[Property]
}*/

export type SignatureAlgorithmFromKeyArgs = {
  key: IKey
}

export type SignatureAlgorithmFromKeyTypeArgs = {
  type: TKeyType
}

export type KeyTypeFromCryptographicSuiteArgs = {
  suite: string
}
