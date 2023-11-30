import { KeyDIDProvider as VeramoKeyDidProvider } from '@veramo/did-provider-key'
import { IAgentContext, IIdentifier, IKeyManager } from '@veramo/core'
import Multibase from 'multibase'
import Multicodec from 'multicodec'
import Debug from 'debug'
import * as u8a from 'uint8arrays'
import {
  generatePrivateKeyHex,
  JWK_JCS_PUB_NAME,
  JWK_JCS_PUB_PREFIX,
  jwkJcsEncode,
  JwkKeyUse,
  TKeyType,
  toJwk,
} from '@sphereon/ssi-sdk-ext.key-utils'

const debug = Debug('did-provider-key')

type IContext = IAgentContext<IKeyManager>

export class SphereonKeyDidProvider extends VeramoKeyDidProvider {
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
    return identifier
  }
}
