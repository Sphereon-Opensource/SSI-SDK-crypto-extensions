import { KeyManager as VeramoKeyManager, AbstractKeyManagementSystem, AbstractKeyStore } from '@veramo/key-manager'

import { IKey, IKeyManagerGetArgs, ManagedKeyInfo, TKeyType } from '@veramo/core'
import { KeyType, SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'
import { ISphereonKeyManager, ISphereonKeyManagerSignArgs, ISphereonKeyManagerVerifyArgs } from '../types/ISphereonKeyManager'
import { calculateJwkThumbprintForKey } from '@sphereon/ssi-sdk-ext.key-utils'

export const sphereonKeyManagerMethods: Array<string> = [
  'keyManagerCreate',
  'keyManagerImport',
  'keyManagerSign',
  'keyManagerVerify',
  'keyManagerListKeys',
]

export class SphereonKeyManager extends VeramoKeyManager {
  private localStore: AbstractKeyStore
  private readonly availableKMSes: Record<string, AbstractKeyManagementSystem>
  readonly localMethods: ISphereonKeyManager

  constructor(options: { store: AbstractKeyStore; kms: Record<string, AbstractKeyManagementSystem> }) {
    super({ store: options.store, kms: options.kms })
    this.localStore = options.store
    this.availableKMSes = options.kms
    const methods = this.methods
    methods.keyManagerVerify = this.keyManagerVerify.bind(this)
    methods.keyManagerListKeys = this.keyManagerListKeys.bind(this)
    this.localMethods = <ISphereonKeyManager>(<unknown>methods)
  }

  private getAvailableKms(name: string): AbstractKeyManagementSystem {
    const kms = this.availableKMSes[name]
    if (!kms) {
      throw Error(`invalid_argument: This agent has no registered KeyManagementSystem with name='${name}'`)
    }
    return kms
  }

  //FIXME extend the IKeyManagerSignArgs.data to be a string or array of strings
  async keyManagerSign(args: ISphereonKeyManagerSignArgs): Promise<string> {
    const keyInfo: IKey = (await this.localStore.get({ kid: args.keyRef })) as IKey
    const kms = this.getAvailableKms(keyInfo.kms)
    if (keyInfo.type === <TKeyType>KeyType.Bls12381G2) {
      return await kms.sign({ keyRef: keyInfo, data: Uint8Array.from(Buffer.from(args.data)) })
    }
    // @ts-ignore
    return await super.keyManagerSign(args)
  }

  async keyManagerVerify(args: ISphereonKeyManagerVerifyArgs): Promise<boolean> {
    const kms = this.getAvailableKms(args.kms)
    if (('verify' in kms && typeof kms.verify === 'function') || kms instanceof SphereonKeyManagementSystem) {
      // @ts-ignore
      return await kms.verify(args)
    }
    throw Error(`KMS ${kms} does not support verification`)
  }

  async keyManagerListKeys(): Promise<ManagedKeyInfo[]> {
    return this.localStore.list({}) // FIXME there are no args it seems
  }

  async keyManagerGet({ kid }: IKeyManagerGetArgs): Promise<IKey> {
    try {
      const key = await this.localStore.get({ kid })
      return key
    } catch (e) {
      const keys: ManagedKeyInfo[] = await this.keyManagerListKeys()
      const foundKey = keys.find(
        (key) =>
          key.publicKeyHex === kid ||
          key.meta?.jwkThumbprint === kid ||
          (key.meta?.jwkThumbprint == null && calculateJwkThumbprintForKey({ key }) === kid)
      )
      if (foundKey) {
        return foundKey as IKey
      } else {
        throw new Error(`Key with kid ${kid} not found`)
      }
    }
  }
}
