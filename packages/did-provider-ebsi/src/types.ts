import { IAgentContext, IKeyManager, MinimalImportableKey, TKeyType } from '@veramo/core'

export type IContext = IAgentContext<IKeyManager>

export type EbsiDIDType = 'NATURAL_PERSON' | 'LEGAL_ENTITY'
export type EbsiDIDPrefix = 'did:ebsi:' | 'did:key:'

export interface EbsiDidSpecInfo {
  type: EbsiDIDType
  method: EbsiDIDPrefix
  version?: number
  didLength?: number
  privateKeyLength?: number
}

export const ebsiDIDSpecInfo: Record<string, EbsiDidSpecInfo> = {
  V1: {
    type: 'LEGAL_ENTITY',
    method: 'did:ebsi:',
    version: 0x01,
    didLength: 16,
    privateKeyLength: 32,
  },
  KEY: {
    type: 'NATURAL_PERSON',
    method: 'did:key:',
  },
}

export interface IKeyOpts extends WithRequiredProperty<Partial<MinimalImportableKey>, 'privateKeyHex'> {
  type?: EbsiKeyType
  purposes?: EbsiPublicKeyPurpose[]
}

// Needed to make a single property required
type WithRequiredProperty<Type, Key extends keyof Type> = Type & {
  [Property in Key]-?: Type[Property]
}

export interface ICreateIdentifierArgs {
  kms?: string
  alias?: string
  type?: EbsiDidSpecInfo
  options?: {
    secp256k1Key?: IKeyOpts
    secp256r1Key?: IKeyOpts
  }
}

export type EbsiKeyType = Extract<TKeyType, 'Secp256k1' | 'Secp256r1'>

export enum EbsiPublicKeyPurpose {
  Authentication = 'authentication',
  AssertionMethod = 'assertionMethod',
  CapabilityInvocation = 'capabilityInvocation',
}
