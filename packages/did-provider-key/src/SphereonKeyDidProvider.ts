import {
  generatePrivateKeyHex,
  JWK_JCS_PUB_NAME,
  JWK_JCS_PUB_PREFIX,
  jwkJcsEncode,
  JwkKeyUse,
  TKeyType,
  toJwk,
} from '@sphereon/ssi-sdk-ext.key-utils'
import { IAgentContext, IIdentifier, IKey, IKeyManager, IService } from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import Debug from 'debug'
import Multibase from 'multibase'
import Multicodec from 'multicodec'
import * as u8a from 'uint8arrays'

const debug = Debug('did-provider-key')

type IContext = IAgentContext<IKeyManager>

export class SphereonKeyDidProvider extends AbstractIdentifierProvider {
  private readonly kms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.kms = options.defaultKms
  }

  async createIdentifier(
    {
      kms,
      options,
    }: {
      kms?: string
      alias?: string
      options?: {
        type?: TKeyType
        codecName?: 'EBSI' | 'jwk_jcs-pub' | Multicodec.CodecName
        key?: {
          privateKeyHex: string
        }
      }
    },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const keyType: TKeyType = options?.type ?? 'Secp256k1'
    let codecName = options?.codecName && options.codecName === 'EBSI' ? JWK_JCS_PUB_NAME : (options?.codecName as Multicodec.CodecName)
    const privateKeyHex = options?.key?.privateKeyHex ?? (await generatePrivateKeyHex(keyType))
    const key = await context.agent.keyManagerImport({ type: keyType, privateKeyHex, kms: kms ?? this.kms })
    let methodSpecificId: string | undefined
    if (codecName === JWK_JCS_PUB_NAME) {
      const jwk = toJwk(key.publicKeyHex, keyType, { use: JwkKeyUse.Signature, key })
      console.log(`FIXME JWK: ${JSON.stringify(toJwk(privateKeyHex, keyType, { use: JwkKeyUse.Signature, key, isPrivateKey: true }), null, 2)}`)
      methodSpecificId = u8a.toString(
        Multibase.encode('base58btc', Multicodec.addPrefix(u8a.fromString(JWK_JCS_PUB_PREFIX.valueOf().toString(16), 'hex'), jwkJcsEncode(jwk)))
      )
    } else if (codecName) {
      methodSpecificId = u8a.toString(
        Multibase.encode('base58btc', Multicodec.addPrefix(codecName as Multicodec.CodecName, u8a.fromString(key.publicKeyHex, 'hex')))
      )
    } else {
      if (keyType === 'Bls12381G2') {
        codecName = 'bls12_381-g2-pub'
      } else if (keyType === 'Secp256k1') {
        codecName = 'secp256k1-pub'
      } else if (keyType === 'Ed25519') {
        codecName = 'ed25519-pub'
      }
      if (codecName) {
        methodSpecificId = u8a
          .toString(Multibase.encode('base58btc', Multicodec.addPrefix(codecName as Multicodec.CodecName, u8a.fromString(key.publicKeyHex, 'hex'))))
          .toString()
      }
    }
    if (!methodSpecificId) {
      throw Error(`Key type ${keyType} is not supported currently for did:key`)
    }
    const identifier: Omit<IIdentifier, 'provider'> = {
      did: 'did:key:' + methodSpecificId,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
    }
    debug('Created', identifier.did)
    console.log('FIXME Created', identifier.did)
    return identifier
  }

  async updateIdentifier(
    args: { did: string; kms?: string | undefined; alias?: string | undefined; options?: any },
    context: IAgentContext<IKeyManager>
  ): Promise<IIdentifier> {
    throw new Error('KeyDIDProvider updateIdentifier not supported yet.')
  }

  async deleteIdentifier(identifier: IIdentifier, context: IContext): Promise<boolean> {
    for (const { kid } of identifier.keys) {
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey({ identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any }, context: IContext): Promise<any> {
    throw Error('KeyDIDProvider addKey not supported')
  }

  async addService({ identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any }, context: IContext): Promise<any> {
    throw Error('KeyDIDProvider addService not supported')
  }

  async removeKey(args: { identifier: IIdentifier; kid: string; options?: any }, context: IContext): Promise<any> {
    throw Error('KeyDIDProvider removeKey not supported')
  }

  async removeService(args: { identifier: IIdentifier; id: string; options?: any }, context: IContext): Promise<any> {
    throw Error('KeyDIDProvider removeService not supported')
  }
}
