import { IAgentContext, IIdentifier, IKeyManager } from '@veramo/core'
import Debug from 'debug'
import { AbstractIdentifierProvider } from '@veramo/did-manager/build/abstract-identifier-provider'
import { DIDDocument } from 'did-resolver'
import { IKey, IService } from '@veramo/core/build/types/IIdentifier'
import * as u8a from 'uint8arrays'
import { ebsiDIDSpecInfo, IContext, ICreateIdentifierArgs } from './types'
import { generatePrivateKeyHex, toMethodSpecificId } from './functions'

const debug = Debug('sphereon:did-provider-ebsi')

export class EbsiDidProvider extends AbstractIdentifierProvider {
  private readonly defaultKms?: string

  constructor(options: { defaultKms?: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
    {
      kms,
      options,
    }: {
      kms?: string
      options?: ICreateIdentifierArgs
    },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if (!options?.type || options.type === ebsiDIDSpecInfo.V1) {
      const privateKeyHex = generatePrivateKeyHex(
        ebsiDIDSpecInfo.V1,
        options?.options?.key?.privateKeyHex ? u8a.fromString(options.options.key.privateKeyHex, 'base16') : undefined
      )
      const key = await context.agent.keyManagerImport({
        type: 'Secp256k1',
        kms: this.assertedKms(kms),
        // meta: options?.options?.meta,
        kid: options?.options?.key?.kid,
        privateKeyHex,
      })

      const methodSpecificId = toMethodSpecificId(ebsiDIDSpecInfo.V1, options?.options?.methodSpecificId)
      const identifier: Omit<IIdentifier, 'provider'> = {
        did: ebsiDIDSpecInfo.V1.method + methodSpecificId,
        controllerKeyId: key.kid,
        keys: [key],
        services: [],
      }
      debug('Created', identifier.did)
      return identifier
    } else if (options.type === ebsiDIDSpecInfo.KEY) {
      throw Error(`Type ${options.type} not supported. Please use @sphereon/ssi-sdk-ext.did-provider-key for Natural Person EBSI DIDs`)
    }
    throw Error(`Type ${options.type} not supported`)
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
}
