import { PEMToBinary } from '@sphereon/ssi-sdk-ext.x509-utils'
import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core'
import {
  ExternalSscdSettings,
  IMusapClient,
  isSignatureAlgorithmType,
  JWSAlgorithm,
  KeyAlgorithm,
  KeyAlgorithmType,
  KeyAttribute,
  KeyGenReq,
  MusapClient,
  MusapKey,
  signatureAlgorithmFromKeyAlgorithm,
  SignatureAlgorithmType,
  SignatureAttribute,
  SignatureFormat,
  SignatureReq,
  SscdType,
} from '@sphereon/musap-react-native'
import { AbstractKeyManagementSystem } from '@veramo/key-manager'
import { TextDecoder } from 'text-encoding'
import { Loggers } from '@sphereon/ssi-types'
import { KeyMetadata } from './index'
import {
  asn1DerToRawPublicKey,
  calculateJwkThumbprintForKey,
  hexStringFromUint8Array,
  isAsn1Der,
  isRawCompressedPublicKey,
  toRawCompressedHexPublicKey,
} from '@sphereon/ssi-sdk-ext.key-utils'

export const logger = Loggers.DEFAULT.get('sphereon:musap-rn-kms')

export class MusapKeyManagementSystem extends AbstractKeyManagementSystem {
  private musapClient: IMusapClient
  private readonly sscdType: SscdType
  private readonly sscdId: string
  private readonly defaultKeyAttributes: Record<string, string> | undefined
  private readonly defaultSignAttributes: Record<string, string> | undefined

  constructor(sscdType?: SscdType, sscdId?: string, opts?: {
    externalSscdSettings?: ExternalSscdSettings,
    defaultKeyAttributes?: Record<string, string>,
    defaultSignAttributes?: Record<string, string>
  }) {
    super()
    try {
      this.musapClient = MusapClient
      this.sscdType = sscdType ? sscdType : 'TEE'
      this.sscdId = sscdId ?? this.sscdType
      this.defaultKeyAttributes = opts?.defaultKeyAttributes
      this.defaultSignAttributes = opts?.defaultSignAttributes

      const enabledSscds = this.musapClient.listEnabledSscds()
      if (!enabledSscds.some(value => value.sscdId == sscdId)) {
        this.musapClient.enableSscd(this.sscdType, this.sscdId, opts?.externalSscdSettings)
      }
    } catch (e) {
      console.error('enableSscd', e)
      throw Error('enableSscd failed')
    }
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    const keysJson: MusapKey[] = (this.musapClient.listKeys()) as MusapKey[]
    return keysJson.map((key) => this.asMusapKeyInfo(key))
  }

  async createKey(args: { type: TKeyType; meta?: KeyMetadata }): Promise<ManagedKeyInfo> {
    const { type, meta } = args
    if (meta === undefined || !('keyAlias' in meta)) {
      return Promise.reject(Error('a unique keyAlias field is required for MUSAP'))
    }

    if (this.sscdType == 'EXTERNAL') {
      const existingKeys: MusapKey[] = (this.musapClient.listKeys()) as MusapKey[]
      const extKey = existingKeys.find(musapKey => musapKey.sscdType as string === 'External Signature') // FIXME returning does not match SscdType enum
      if (extKey) {
        extKey.algorithm = 'eccp256r1' // FIXME MUSAP announces key as rsa2k, but it's actually EC
        return this.asMusapKeyInfo(extKey)
      }
      return Promise.reject(Error(`No external key was bound yet for sscd ${this.sscdId}`))
    }

    const keyGenReq = {
      keyAlgorithm: this.mapKeyTypeToAlgorithmType(type),
      keyUsage: 'keyUsage' in meta ? (meta.keyUsage as string) : 'sign',
      keyAlias: meta.keyAlias as string,
      attributes: this.recordToKeyAttributes({ ...this.defaultKeyAttributes, ...('attributes' in meta ? meta.attributes : {}) }),
      role: 'role' in meta ? (meta.role as string) : 'administrator',
    } satisfies KeyGenReq

    try {
      const generatedKeyUri = await this.musapClient.generateKey(this.sscdType, keyGenReq)
      if (generatedKeyUri) {
        logger.debug('Generated key:', generatedKeyUri)
        const key = this.musapClient.getKeyByUri(generatedKeyUri)
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
      case 'ecc_ed25519':
        return 'Ed25519'
      case 'rsa2k':
      case 'rsa4k':
        return 'RSA'
      default:
        throw new Error(`Key type ${type} is not supported.`)
    }
  }

  async deleteKey({ kid }: { kid: string }): Promise<boolean> {
      try {
        const key: MusapKey = this.musapClient.getKeyById(kid) as MusapKey
        if (key.sscdType as string === 'External Signature') {
          return true // we can't remove a eSim key because this would mean onboarding again
        }
        void this.musapClient.removeKey(kid)
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

  async sign(args: {
    keyRef: Pick<IKey, 'kid'>;
    algorithm?: string;
    data: Uint8Array;
    [x: string]: any
  }): Promise<string> {
    if (!args.keyRef) {
      throw new Error('key_not_found: No key ref provided')
    }

    const data = new TextDecoder().decode(args.data as Uint8Array)

    const key: MusapKey = this.musapClient.getKeyById(args.keyRef.kid) as MusapKey
    if (key.sscdType as string === 'External Signature') {
      key.algorithm = 'eccp256r1' // FIXME MUSAP announces key as rsa2k, but it's actually EC
    }
    const signatureReq: SignatureReq = {
      keyUri: key.keyUri,
      data,
      algorithm: this.determineAlgorithm(args.algorithm, key.algorithm),
      displayText: args.displayText,
      transId: args.transId,
      format: (args.format as SignatureFormat) ?? 'RAW',
      attributes: this.recordToSignatureAttributes({ ...this.defaultSignAttributes, ...args.attributes }),
    }
    return this.musapClient.sign(signatureReq)
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('importKey is not implemented for MusapKeyManagementSystem.')
  }

  private asMusapKeyInfo(args: MusapKey): ManagedKeyInfo {
    const { keyId, publicKey, ...metadata }: KeyMetadata = { ...args }
    const keyType = this.mapAlgorithmTypeToKeyType(args.algorithm)

    const pemBinary = PEMToBinary(args.publicKey.pem) // The der is flawed, it's not binary but a string [123, 4567]
    const publicKeyBinary = isAsn1Der(pemBinary) ? asn1DerToRawPublicKey(pemBinary, keyType) : pemBinary
    const publicKeyHex = isRawCompressedPublicKey(publicKeyBinary) // TODO In the future I think it's better to have an option in KeyGenReq to specify which public key format we want back. Now it's different in iOS vs Android and we need to handle that inconsistency afterwards
      ? hexStringFromUint8Array(publicKeyBinary)
      : toRawCompressedHexPublicKey(publicKeyBinary, keyType)
    const keyInfo: Partial<ManagedKeyInfo> = {
      kid: keyId,
      type: keyType,
      publicKeyHex,
      meta: metadata,
    }

    const jwkThumbprint = calculateJwkThumbprintForKey({ key: keyInfo as ManagedKeyInfo })
    keyInfo.meta = { ...keyInfo.meta, jwkThumbprint }
    return keyInfo as ManagedKeyInfo
  }

  sharedSecret(args: { myKeyRef: Pick<IKey, 'kid'>; theirKey: Pick<IKey, 'publicKeyHex' | 'type'> }): Promise<string> {
    throw new Error('Not supported.')
  }

  private recordToKeyAttributes(record?: Record<string, string>): KeyAttribute[] {
    if (!record) {
      return []
    }
    return Object.entries(record).map(([key, value]) => ({
      name: key,
      value,
    }))
  }

  private recordToSignatureAttributes(record?: Record<string, string>): SignatureAttribute[] {
    if (!record) {
      return []
    }
    return Object.entries(record).map(([key, value]) => ({
      name: key,
      value,
    }))
  }
}
