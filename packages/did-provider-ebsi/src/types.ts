import { IAgentContext, IKeyManager, MinimalImportableKey } from '@veramo/core'

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

export interface IKeyOpts {
  methodSpecificId?: string // method specific id for import
  key?: WithRequiredProperty<Partial<MinimalImportableKey>, 'privateKeyHex'> // Optional key to import with only privateKeyHex mandatory. If not specified a key with random kid will be created
  /*type?: Key // The key type. Defaults to Secp256k1
  use?: KeyUse // The key use*/
}

// Needed to make a single property required
type WithRequiredProperty<Type, Key extends keyof Type> = Type & {
  [Property in Key]-?: Type[Property]
}

export interface ICreateIdentifierArgs {
  kms?: string
  alias?: string
  type?: EbsiDidSpecInfo
  options?: IKeyOpts
}
