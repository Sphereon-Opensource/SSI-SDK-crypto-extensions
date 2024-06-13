import { IAgentContext, IDIDManager, IIdentifier, IKeyManager } from '@veramo/core'
import Debug from 'debug'
import { AbstractIdentifierProvider } from '@veramo/did-manager/build/abstract-identifier-provider'
import { IKey, IService } from '@veramo/core/build/types/IIdentifier'
import { ApiOpts, ebsiDIDSpecInfo, IContext, ICreateIdentifierArgs, UpdateIdentifierParams } from './types'
import { createEbsiDid, generateEbsiKeyPair, generateMethodSpecificId } from './functions'

const debug = Debug('sphereon:did-provider-ebsi')

export class EbsiDidProvider extends AbstractIdentifierProvider {
  private readonly defaultKms?: string
  private readonly apiOpts?: ApiOpts

  constructor(options: { defaultKms?: string; apiOpts?: ApiOpts }) {
    super()
    this.defaultKms = options.defaultKms
    this.apiOpts = options.apiOpts
  }

  async createIdentifier(args: ICreateIdentifierArgs, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
    const { type, options, kms, alias } = { ...args }

    if (!type || type === ebsiDIDSpecInfo.V1) {
      const secp256k1ManagedKeyInfo = await generateEbsiKeyPair(
        {
          keyOpts: options?.secp256k1Key,
          keyType: 'Secp256k1',
          kms: kms ?? this.defaultKms,
        },
        context
      )
      const secp256r1ManagedKeyInfo = await generateEbsiKeyPair(
        {
          keyOpts: options?.secp256r1Key,
          keyType: 'Secp256r1',
          kms: kms ?? this.defaultKms,
        },
        context
      )

      const methodSpecificId = generateMethodSpecificId(ebsiDIDSpecInfo.V1)
      const identifier: Omit<IIdentifier, 'provider'> = {
        did: ebsiDIDSpecInfo.V1.method + methodSpecificId,
        controllerKeyId: secp256k1ManagedKeyInfo.kid,
        keys: [secp256k1ManagedKeyInfo, secp256r1ManagedKeyInfo],
        alias,
        services: [],
      }
      const id = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)

      if (options === undefined) {
        throw new Error(`Options must be provided ${JSON.stringify(options)}`)
      }

      await createEbsiDid(
        {
          identifier,
          secp256k1ManagedKeyInfo,
          secp256r1ManagedKeyInfo,
          id,
          from: options.from,
          notBefore: options.notBefore,
          notAfter: options.notAfter,
          apiOpts: options.apiOpts ?? this.apiOpts,
        },
        context
      )

      debug('Created', identifier.did)
      return identifier
    } else if (type === ebsiDIDSpecInfo.KEY) {
      throw new Error(`Type ${type} not supported. Please use @sphereon/ssi-sdk-ext.did-provider-key for Natural Person EBSI DIDs`)
    }
    throw new Error(`Type ${type} not supported`)
  }

  addKey(
    args: {
      identifier: IIdentifier
      key: IKey
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw new Error(`Not (yet) implemented for the EBSI did provider`)
  }

  addService(
    args: {
      identifier: IIdentifier
      service: IService
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw new Error(`Not (yet) implemented for the EBSI did provider`)
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
    throw new Error(`Not (yet) implemented for the EBSI did provider`)
  }

  removeService(
    args: {
      identifier: IIdentifier
      id: string
      options?: any
    },
    context: IAgentContext<IKeyManager>
  ): Promise<any> {
    throw new Error(`Not (yet) implemented for the EBSI did provider`)
  }

  // TODO How does it work? Not inferable from the api: https://hub.ebsi.eu/apis/pilot/did-registry/v5/post-jsonrpc#updatebasedocument
  async updateIdentifier(args: UpdateIdentifierParams, context: IAgentContext<IKeyManager & IDIDManager>): Promise<IIdentifier> {
    throw new Error(`Not (yet) implemented for the EBSI did provider`)
  }
}
