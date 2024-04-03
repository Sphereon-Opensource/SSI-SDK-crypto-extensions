import {IAgentContext, IIdentifier, IKeyManager, MinimalImportableKey} from '@veramo/core'
import Debug from 'debug'
import {AbstractIdentifierProvider} from '@veramo/did-manager/build/abstract-identifier-provider'
import {DIDDocument} from 'did-resolver'
import {IKey, IService} from '@veramo/core/build/types/IIdentifier'
import * as u8a from 'uint8arrays'
import {
    ebsiDIDSpecInfo,
    EbsiPublicKeyPurpose,
    IContext,
    ICreateIdentifierArgs,
    IKeyOpts,
    KeyType,
    VerificationMethod
} from './types'
import {generateEbsiPrivateKeyHex, toMethodSpecificId} from './functions'

const debug = Debug('sphereon:did-provider-ebsi')

export class EbsiDidProvider extends AbstractIdentifierProvider {
  private readonly defaultKms?: string

  constructor(options: { defaultKms?: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(args: ICreateIdentifierArgs, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
    const { type, options, kms, alias } = { ...args }
    if (!type || type === ebsiDIDSpecInfo.V1) {

      const secp256k1ManagedKeyInfo = await this.generateEbsiKeyPair(
        {
          keyOpts: {
              ...options?.secp256k1,
              type: this.assertedKeyType({ key: options?.secp256k1, keyType: KeyType.Secp256k1 }),
              purposes: this.assertedPurposes({ keyType: KeyType.Secp256k1, purposes: (options?.secp256k1 as VerificationMethod)?.purposes })
          },
          alias,
          kms,
        },
        context
      )
        const secp256r1ManagedKeyInfo = await this.generateEbsiKeyPair(
        {
          keyOpts: {
              ...options?.secp256r1,
              type: this.assertedKeyType({ key: options?.secp256r1, keyType: KeyType.Secp256r1 }),
              purposes: this.assertedPurposes({ keyType: KeyType.Secp256r1, purposes: (options?.secp256r1 as VerificationMethod)?.purposes })
          },
          alias,
          kms,
        },
        context
      )

      const methodSpecificId = toMethodSpecificId(ebsiDIDSpecInfo.V1, options?.methodSpecificId)
      const identifier: Omit<IIdentifier, 'provider'> = {
        did: ebsiDIDSpecInfo.V1.method + methodSpecificId,
        controllerKeyId: secp256k1ManagedKeyInfo.kid,
        keys: [secp256k1ManagedKeyInfo, secp256r1ManagedKeyInfo],
        services: [],
      }
      debug('Created', identifier.did)
      return identifier
    } else if (type === ebsiDIDSpecInfo.KEY) {
      throw Error(`Type ${type} not supported. Please use @sphereon/ssi-sdk-ext.did-provider-key for Natural Person EBSI DIDs`)
    }
    throw Error(`Type ${type} not supported`)
  }

  private async generateEbsiKeyPair(
    args: { keyOpts?: IKeyOpts | VerificationMethod; alias?: string; kms?: string },
    context: IAgentContext<IKeyManager>
  ) {
    let privateKeyHex = generateEbsiPrivateKeyHex(
      ebsiDIDSpecInfo.V1,
      args.keyOpts?.key?.privateKeyHex ? u8a.fromString(args.keyOpts.key.privateKeyHex, 'base16') : undefined
    )
    if (privateKeyHex.startsWith('0x')) {
      privateKeyHex = privateKeyHex.substring(2)
    }
    if (!privateKeyHex || privateKeyHex.length !== 64) {
      throw Error('Private key should be 32 bytes / 64 chars hex')
    }

    const keyManagerImportArgs: MinimalImportableKey = {
      type: args.keyOpts?.type!, // It's safe to use '!', a default value is set
      kms: this.assertedKms(args.kms),
      kid: args.keyOpts?.kid,
      privateKeyHex,
    }

    if (args?.keyOpts && 'purposes' in args.keyOpts) {
      keyManagerImportArgs.meta = { purposes: [...args.keyOpts.purposes] }
    }

    return await context.agent.keyManagerImport(keyManagerImportArgs)
  }

  addKey(
    args: {
      identifier: IIdentifier
      key: IKey
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw Error(`Not (yet) implemented for the EBSI did provider`)
  }

  addService(
    args: {
      identifier: IIdentifier
      service: IService
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw Error(`Not (yet) implemented for the EBSI did provider`)
  }

  deleteIdentifier(args: IIdentifier, context: IAgentContext<IKeyManager>): Promise<boolean> {
    return Promise.resolve(true)
  }

  removeKey(
    args: {
      identifier: IIdentifier
      kid: string
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw Error(`Not (yet) implemented for the EBSI did provider`)
  }

  removeService(
    args: {
      identifier: IIdentifier
      id: string
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw Error(`Not (yet) implemented for the EBSI did provider`)
  }

  updateIdentifier(
    args: {
      did: string
      document: Partial<DIDDocument>
      options?: { [p: string]: any }
    },
    context: IAgentContext<IKeyManager>
  ): Promise<IIdentifier> {
    throw Error(`Not (yet) implemented for the EBSI did provider`)
  }

  private assertedKms(kms?: string) {
    const result = kms ?? this.defaultKms
    if (!!result) {
      return result
    }
    throw Error('no KMS supplied')
  }

  private assertedKeyType = (args: { key?: IKeyOpts; keyType: KeyType }): KeyType => {
      if (!args.key?.type) {
          return args.keyType
      }
      return args.key.type
  }

  private assertedPurposes = (args: { keyType: KeyType; purposes: EbsiPublicKeyPurpose[] }) => {
      if (args.purposes) {
          return args.purposes
      }
      switch (args.keyType) {
          case 'Secp256k1': {
              return [ EbsiPublicKeyPurpose.CapabilityInvocation ]
          }
          case 'Secp256r1': {
              return [ EbsiPublicKeyPurpose.AssertionMethod, EbsiPublicKeyPurpose.Authentication ]
          }
          default:
              throw new Error(`Unsupported key type: ${args.keyType}`)
      }
  }
}
