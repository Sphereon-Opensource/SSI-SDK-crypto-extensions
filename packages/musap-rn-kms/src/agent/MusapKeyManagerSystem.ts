import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core'
import { KeyGenReq, MusapKey, MusapModuleType, SignatureAlgorithmType, SignatureFormat, SignatureReq } from '@sphereon/musap-react-native'
import { SscdType } from '@sphereon/musap-react-native/src/types/musap-types'
import { KeyManagementSystem } from '@veramo/kms-local'
import { AbstractPrivateKeyStore } from '@veramo/key-manager'

export class MusapKeyManagementSystem extends KeyManagementSystem {
  private musapKeyStore: MusapModuleType

  constructor(keyStore: MusapModuleType) {
    super(keyStore as unknown as AbstractPrivateKeyStore)
    this.musapKeyStore = keyStore
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    try {
      const keysJson: MusapKey[] = (await this.musapKeyStore.listKeys()) as MusapKey[]
      return keysJson.map((key) => this.asMusapKeyInfo(key))
    } catch (error) {
      console.error('Failed to list keys:', error)
      throw error
    }
  }

  async createKey(args: { type: TKeyType; meta?: { keyGenReq: KeyGenReq } }): Promise<ManagedKeyInfo> {
    if (!args.meta?.keyGenReq) {
      throw new Error('KeyGen request is not present.')
    }
    try {
      const generatedKey = await this.generateKeyWrapper(args.type as SscdType, args.meta.keyGenReq)
      if (generatedKey) {
        console.log('Generated key:', generatedKey)
        return this.asMusapKeyInfo(generatedKey)
      } else {
        console.log('Failed to generate key')
        throw new Error('Failed to generate key')
      }
    } catch (error) {
      console.error('An error occurred:', error)
      throw error
    }
  }

  async generateKeyWrapper(type: SscdType, keyGenRequest: KeyGenReq): Promise<MusapKey | undefined> {
    return new Promise((resolve) => {
      //todo: casting to SscdType
      this.musapKeyStore.generateKey(type, keyGenRequest, (error: any | undefined, keyUri: string | undefined) => {
        if (this.musapKeyStore.listEnabledSscds()[0].sscdInfo.sscdName === 'SE' && error) {
          // Security Enclave handles both error and result in error
          console.log(error)
          resolve(undefined)
        } else if (error) {
          console.log(error)
          resolve(undefined)
        } else if (keyUri) {
          console.log(`Key successfully generated: ${keyUri}`)
          const key = this.musapKeyStore.getKeyByUri(keyUri) as MusapKey
          resolve(key)
        } else {
          resolve(undefined)
        }
      })
    })
  }

  async deleteKey({ kid }: { kid: string }): Promise<boolean> {
    try {
      // TODO: Implement deleteKey logic
      return true
    } catch (error) {
      console.error('Failed to delete key:', error)
      throw error
    }
  }

  async sign(args: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array; [x: string]: any }): Promise<string> {
    return new Promise(async (resolve) => {
      if (!args.keyRef) {
        throw new Error('key_not_found: No key ref provided')
      }
      const key: MusapKey = (await this.musapKeyStore.getKeyByUri(args.keyRef as unknown as string)) as MusapKey
      const decoder = new TextDecoder('utf-8')
      const signatureReq: SignatureReq = {
        key,
        data: decoder.decode(args.data),
        algorithm: args.algorithm as SignatureAlgorithmType,
        displayText: args.displayText,
        transId: args.transId,
        format: args.format as SignatureFormat,
        attributes: args.attributes,
      }
      await this.musapKeyStore.sign(signatureReq, (error: string | undefined, signed: string | undefined) => {
        return signed
      })
    })
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('Not implemented.')
  }

  private asMusapKeyInfo(args: MusapKey): ManagedKeyInfo {
    return args as unknown as ManagedKeyInfo
  }
}
