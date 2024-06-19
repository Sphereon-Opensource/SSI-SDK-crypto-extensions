import { IAgentContext, IDIDManager, IIdentifier, IKeyManager } from '@veramo/core'
import { IKey, IService } from '@veramo/core/build/types/IIdentifier'
import { AbstractIdentifierProvider } from '@veramo/did-manager/build/abstract-identifier-provider'
import Debug from 'debug'
import { createEbsiDidOnLedger, generateEbsiMethodSpecificId, generateOrUseEbsiKeyPair, randomRpcId } from './functions'
import { ApiOpts, EBSI_DID_SPEC_INFOS, IContext, ICreateIdentifierArgs, UpdateIdentifierParams } from './types'

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
    const { type, options, kms, alias } = args
    const { notBefore, notAfter, secp256k1Key, secp256r1Key, bearerToken, from, executeLedgerOperation = false } = { ...options }

    if (executeLedgerOperation && !bearerToken) {
      throw new Error('Bearer token must be provided to execute ledger operation')
    }
    const rpcId = options?.rpcId ?? randomRpcId()

    if (type === EBSI_DID_SPEC_INFOS.KEY) {
      throw new Error(`Type ${type} not supported. Please use @sphereon/ssi-sdk-ext.did-provider-key for Natural Person EBSI DIDs`)
    }

    const secp256k1ImportKey = await generateOrUseEbsiKeyPair(
      {
        keyOpts: secp256k1Key,
        keyType: 'Secp256k1',
        kms: kms ?? this.defaultKms,
      },
      context
    )
    const secp256k1ManagedKeyInfo = await context.agent.keyManagerImport(secp256k1ImportKey)

    const secp256r1ImportKey = await generateOrUseEbsiKeyPair(
      {
        keyOpts: secp256r1Key,
        keyType: 'Secp256r1',
        kms: kms ?? this.defaultKms,
      },
      context
    )

    const secp256r1ManagedKeyInfo = await context.agent.keyManagerImport(secp256r1ImportKey)

    const methodSpecificId = generateEbsiMethodSpecificId(EBSI_DID_SPEC_INFOS.V1)
    const identifier: Omit<IIdentifier, 'provider'> = {
      did: `${EBSI_DID_SPEC_INFOS.V1.method}${methodSpecificId}`,
      controllerKeyId: secp256k1ManagedKeyInfo.kid,
      keys: [secp256k1ManagedKeyInfo, secp256r1ManagedKeyInfo],
      alias,
      services: [],
    }

    if (executeLedgerOperation) {
      if (!from) {
        // TODO: The agent should be able to devise the from, as we have access to the keys etc.
        throw Error(`No from provided, whilst we are performing a ledger operation!`)
      }
      await createEbsiDidOnLedger(
        {
          identifier,
          secp256k1ManagedKeyInfo,
          secp256r1ManagedKeyInfo,
          bearerToken: bearerToken!,
          rpcId,
          from,
          notBefore: notBefore ?? Date.now() / 1000,
          notAfter: notAfter ?? Number.MAX_SAFE_INTEGER,
          apiOpts: { ...this.apiOpts, ...options?.apiOpts },
        },
        context
      )
    }

    debug('Created', identifier.did)
    return identifier
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
