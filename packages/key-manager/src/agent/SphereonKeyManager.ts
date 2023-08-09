import { KeyManager, AbstractKeyManagementSystem, AbstractKeyStore } from '@veramo/key-manager'

import { IKey, TKeyType } from '@veramo/core'
import {KeyType, SphereonKeyManagementSystem} from '@sphereon/ssi-sdk-ext.kms-local'
import { ISphereonKeyManager, ISphereonKeyManagerSignArgs, ISphereonKeyManagerVerifyArgs } from '../types/ISphereonKeyManager'

export class SphereonKeyManager extends KeyManager {
  private localStore: AbstractKeyStore
  private readonly localKms: Record<string, AbstractKeyManagementSystem>
  readonly localMethods: ISphereonKeyManager

  constructor(options: { store: AbstractKeyStore; kms: Record<string, AbstractKeyManagementSystem> }) {
    super({ store: options.store, kms: options.kms })
    this.localStore = options.store
    this.localKms = options.kms
    const methods = this.methods
    methods.keyManagerVerify = this.keyManagerVerify.bind(this)
    this.localMethods = <ISphereonKeyManager>(<unknown>methods)
  }

  private getLocalKms(name: string): AbstractKeyManagementSystem {
    const kms = this.localKms[name]
    if (!kms) {
      throw Error(`invalid_argument: This agent has no registered KeyManagementSystem with name='${name}'`)
    }
    return kms
  }

  //FIXME extend the IKeyManagerSignArgs.data to be a string or array of strings
  async keyManagerSign(args: ISphereonKeyManagerSignArgs): Promise<string> {
    const keyInfo: IKey = (await this.localStore.get({ kid: args.keyRef })) as IKey
    const kms = this.getLocalKms(keyInfo.kms)
    if (keyInfo.type === <TKeyType>KeyType.Bls12381G2) {
      return await kms.sign({ keyRef: keyInfo, data: Uint8Array.from(Buffer.from(args.data)) })
    }
    // @ts-ignore
    return await super.keyManagerSign(args)
  }

  async keyManagerVerify(args: ISphereonKeyManagerVerifyArgs): Promise<boolean> {
    const kms = this.getLocalKms(args.kms)
    if (('verify' in kms && typeof kms.verify === 'function') || kms instanceof SphereonKeyManagementSystem) {
      // @ts-ignore
      return await kms.verify(args)
    }
    throw Error(`KMS ${kms} does not support verification`)
  }
}
