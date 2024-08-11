import { PEMToBinary } from '@sphereon/ssi-sdk-ext.x509-utils'
import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core'
import {
  isSignatureAlgorithmType,
  JWSAlgorithm,
  KeyAlgorithm,
  KeyAlgorithmType,
  KeyGenReq,
  MusapKey,
  MusapModule,
  MusapModuleType,
  signatureAlgorithmFromKeyAlgorithm,
  SignatureAlgorithmType,
  SignatureFormat,
  SignatureReq,
} from '@sphereon/musap-react-native'
import { KeyAttribute, SscdType } from '@sphereon/musap-react-native'
import { AbstractKeyManagementSystem } from '@veramo/key-manager'
import { TextDecoder } from 'text-encoding'
import { Loggers } from '@sphereon/ssi-types'
import { KeyMetadata } from './index'
import {
  asn1DerToRawPublicKey,
  hexStringFromUint8Array,
  isAsn1Der,
  isRawCompressedPublicKey,
  toRawCompressedHexPublicKey,
} from '@sphereon/ssi-sdk-ext.key-utils'

export const logger = Loggers.DEFAULT.get('sphereon:musap-rn-kms')

export class MusapKeyManagementSystem extends AbstractKeyManagementSystem {
  private musapKeyStore: MusapModuleType
  private sscdType: SscdType

  constructor(sscdType?: SscdType) {
    super()
    try {
      this.musapKeyStore = MusapModule
      this.sscdType = sscdType ? sscdType : 'TEE'
      this.musapKeyStore.enableSscd(this.sscdType)
    } catch (e) {
      console.error('enableSscd', e)
      throw Error('enableSscd failed')
    }
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    const keysJson: MusapKey[] = (await this.musapKeyStore.listKeys()) as MusapKey[]
    return keysJson.map((key) => this.asMusapKeyInfo(key))
  }

  async createKey(args: { type: TKeyType; meta?: KeyMetadata }): Promise<ManagedKeyInfo> {
    const { type, meta } = args
    if (meta === undefined || !('keyAlias' in meta)) {
      return Promise.reject(Error('a unique keyAlias field is required for MUSAP'))
    }

    const keyGenReq = {
      keyAlgorithm: this.mapKeyTypeToAlgorithmType(type),
      keyUsage: 'keyUsage' in meta ? (meta.keyUsage as string) : 'sign',
      keyAlias: meta.keyAlias as string,
      attributes: 'attributes' in meta ? (meta.attributes as KeyAttribute[]) : [],
      role: 'role' in meta ? (meta.role as string) : 'administrator',
    } satisfies KeyGenReq

    try {
      const generatedKeyUri = await this.musapKeyStore.generateKey(this.sscdType, keyGenReq)
      if (generatedKeyUri) {
        logger.debug('Generated key:', generatedKeyUri)
        const key = await this.musapKeyStore.getKeyByUri(generatedKeyUri)
        return this.asMusapKeyInfo(key)
      } else {
        return Promise.reject(new Error('Failed to generate key. No key URI'))
      }
    } catch (error) {
      logger.error('An error occurred:', error)
      throw error
    }
  }

  private mapKeyTypeToAlgorithmType = (type: TKeyType): KeyAlgorithmType => {
    switch (type) {
      case 'Secp256k1':
        return 'ECCP256K1'
      case 'Secp256r1':
        return 'ECCP256R1'
      case 'RSA':
        return 'RSA2K'
      default:
        throw new Error(`Key type ${type} is not supported by MUSAP`)
    }
  }

  private mapAlgorithmTypeToKeyType = (type: KeyAlgorithm): TKeyType => {
    switch (type) {
      case 'eccp256k1':
        return 'Secp256k1'
      case 'eccp256r1':
        return 'Secp256r1'
      case 'rsa4k':
        return 'RSA'
      default:
        throw new Error(`Key type ${type} is not supported.`)
    }
  }

  async deleteKey({ kid }: { kid: string }): Promise<boolean> {
    try {
      this.musapKeyStore.removeKey(kid)
      return true
    } catch (error) {
      console.warn('Failed to delete key:', error)
      return false
    }
  }

  private determineAlgorithm(providedAlgorithm: string | undefined, keyAlgorithm: KeyAlgorithm): SignatureAlgorithmType {
    if (providedAlgorithm === undefined) {
      return signatureAlgorithmFromKeyAlgorithm(keyAlgorithm)
    }

    if (isSignatureAlgorithmType(providedAlgorithm)) {
      return providedAlgorithm
    }

    // Veramo translates TKeyType to JWSAlgorithm
    return signatureAlgorithmFromKeyAlgorithm(providedAlgorithm as JWSAlgorithm)
  }

  async sign(args: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array; [x: string]: any }): Promise<string> {
    if (!args.keyRef) {
      throw new Error('key_not_found: No key ref provided')
    }

    const data = new TextDecoder().decode(args.data as Uint8Array)

    const key: MusapKey = this.musapKeyStore.getKeyById(args.keyRef.kid) as MusapKey
    const signatureReq: SignatureReq = {
      keyUri: key.keyUri,
      data,
      algorithm: this.determineAlgorithm(args.algorithm, key.algorithm),
      displayText: args.displayText,
      transId: args.transId,
      format: (args.format as SignatureFormat) ?? 'RAW',
      attributes: args.attributes,
    }
    return this.musapKeyStore.sign(signatureReq)
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('importKey is not implemented for MusapKeyManagementSystem.')
  }

  private asMusapKeyInfo(args: MusapKey): ManagedKeyInfo {
    const keyType = this.mapAlgorithmTypeToKeyType(args.algorithm)
    const pemBinary = PEMToBinary(args.publicKey.pem) // The der is flawed, it's not binary but a string [123, 4567]
    const publicKeyBinary = isAsn1Der(pemBinary) ? asn1DerToRawPublicKey(pemBinary, keyType) : pemBinary
    const publicKeyHex = isRawCompressedPublicKey(publicKeyBinary) // TODO In the future I think it's better to have an option in KeyGenReq to specify which public key format we want back. Now it's different in iOS vs Android and we need to handle that inconsistency afterwards
      ? hexStringFromUint8Array(publicKeyBinary)
      : toRawCompressedHexPublicKey(publicKeyBinary, keyType)
    const keyInfo: Partial<ManagedKeyInfo> = {
      kid: args.keyId,
      type: keyType,
      publicKeyHex: publicKeyHex,
      meta: {
        ...args,
      },
    }
    return keyInfo as ManagedKeyInfo
  }

  sharedSecret(args: { myKeyRef: Pick<IKey, 'kid'>; theirKey: Pick<IKey, 'publicKeyHex' | 'type'> }): Promise<string> {
    throw new Error('Not supported.')
  }
}
