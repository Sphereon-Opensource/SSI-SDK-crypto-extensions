import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core'
import { KeyGenReq, MusapKey, MusapModuleType, SignatureReq } from '@sphereon/musap-react-native'
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

  async createKey(args: { type: TKeyType; meta?: { keyMetadata: KeyGenReq } }): Promise<ManagedKeyInfo> {
    try {
      const generatedKey = await this.generateKeyWrapper(args.type as SscdType, args.meta?.keyMetadata)
      if (generatedKey) {
        // Use the generated key
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

  async generateKeyWrapper(type: SscdType, keyGenRequest: any): Promise<MusapKey | undefined> {
    return new Promise((resolve) => {
      //todo: casting to SscdType
      this.musapKeyStore.generateKey(type, keyGenRequest, (error: any, keyUri: string) => {
        if (this.musapKeyStore.listEnabledSscds()[0].sscdInfo.sscdName === 'SE' && error) {
          // Security Enclave handles both error and result in error
          console.log(error)
          resolve(undefined)
        } else if (error) {
          console.log(error)
          resolve(undefined)
        } else if (keyUri) {
          console.log(`Key successfully generated: ${keyUri}`)
          // Works on Android
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

  async sign(args: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array; callback?: Function; [x: string]: any }): Promise<string> {
    if (!args.callback) {
      throw new Error('Musap callback is missing.')
    }
    try {
      const decoder = new TextDecoder('utf-8')
      const value = decoder.decode(args.data)
      const signatureReq: SignatureReq = {
        key: args.key,
        data: value,
        displayText: args.displayText,
        algorithm: args.algorithm as unknown as
          | 'SHA256withECDSA'
          | 'SHA384withECDSA'
          | 'SHA512withECDSA'
          | 'NONEwithECDSA'
          | 'NONEwithEdDSA'
          | 'SHA256withRSA'
          | 'SHA384withRSA'
          | 'SHA512withRSA'
          | 'NONEwithRSA'
          | 'SHA256withRSASSA-PSS'
          | 'SHA384withRSASSA-PSS'
          | 'SHA512withRSASSA-PSS'
          | 'NONEwithRSASSA-PSS'
          | undefined,
        format: args.format,
        attributes: args.attributes,
        transId: args.transId,
      }
      await this.musapKeyStore.sign(signatureReq, args.callback)
      // TODO: Read the data from the callback
      return '' as string
    } catch (error) {
      console.error('Failed to sign data:', error)
      throw error
    }
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('Not implemented.')
  }

  private asMusapKeyInfo(args: MusapKey): ManagedKeyInfo {
    return args as unknown as ManagedKeyInfo
  }
}
