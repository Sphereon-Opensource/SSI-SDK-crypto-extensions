import { KeyDIDProvider } from '@veramo/did-provider-key'
import { IAgentContext, IIdentifier, IKeyManager } from '@veramo/core'
import Multibase from 'multibase'
import Multicodec from 'multicodec'
import Debug from 'debug'
import { JWK_JCS_PUB_NAME, JWK_JCS_PUB_PREFIX, jwkJcsEncode, JwkKeyUse, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'

const debug = Debug('did-provider-key')

type IContext = IAgentContext<IKeyManager>

export class SphereonKeyDidProvider extends KeyDIDProvider {
  private readonly kms: string

  constructor(options: { defaultKms: string }) {
    super(options)
    this.kms = options.defaultKms
  }

  async createIdentifier(
    {
      kms,
      options,
    }: {
      kms?: string
      alias?: string
      options?: any
    },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if (options?.type === 'Bls12381G2') {
      const key = await context.agent.keyManagerCreate({ kms: kms || this.kms, type: 'Bls12381G2' })

      const methodSpecificId = Buffer.from(
        Multibase.encode('base58btc', Multicodec.addPrefix('bls12_381-g2-pub', Buffer.from(key.publicKeyHex, 'hex')))
      ).toString()

      const identifier: Omit<IIdentifier, 'provider'> = {
        did: 'did:key:' + methodSpecificId,
        controllerKeyId: key.kid,
        keys: [key],
        services: [],
      }
      debug('Created', identifier.did)
      return identifier
    } else if (options?.type?.toLowerCase()?.includes('ebsi') || options?.type?.toLowerCase() === JWK_JCS_PUB_NAME.toLowerCase()) {
      const key = await context.agent.keyManagerCreate({ kms: kms || this.kms, type: 'Secp256k1' })
      const jwk = toJwk(key.publicKeyHex, 'Secp256k1', { use: JwkKeyUse.Signature, key })

      // todo: Remove buffers, and remove redundant code
      const methodSpecificId = Buffer.from(
        Multibase.encode('base58btc', Multicodec.addPrefix(Uint8Array.of(JWK_JCS_PUB_PREFIX.valueOf()), jwkJcsEncode(jwk)))
      ).toString()
      const identifier: Omit<IIdentifier, 'provider'> = {
        did: 'did:key:' + methodSpecificId,
        controllerKeyId: key.kid,
        keys: [key],
        services: [],
      }
      debug('Created', identifier.did)
      return identifier
    }
    return super.createIdentifier({ kms, options }, context)
  }
}
