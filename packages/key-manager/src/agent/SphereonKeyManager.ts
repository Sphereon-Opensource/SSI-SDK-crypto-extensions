import { calculateJwkThumbprintForKey } from '@sphereon/ssi-sdk-ext.key-utils'
import { IKey, KeyMetadata, ManagedKeyInfo } from '@veramo/core'
import { AbstractKeyManagementSystem, AbstractKeyStore, KeyManager as VeramoKeyManager } from '@veramo/key-manager'
import {
  hasKeyOptions,
  ISphereonKeyManager,
  ISphereonKeyManagerCreateArgs,
  ISphereonKeyManagerHandleExpirationsArgs,
  ISphereonKeyManagerSignArgs,
  ISphereonKeyManagerVerifyArgs,
} from '../types/ISphereonKeyManager'

export const sphereonKeyManagerMethods: Array<string> = [
  'keyManagerCreate',
  'keyManagerImport',
  'keyManagerSign',
  'keyManagerVerify',
  'keyManagerListKeys',
  'keyManagerHandleExpirations',
]

export class SphereonKeyManager extends VeramoKeyManager {
  // local store reference, given the superclass store is private, and we need additional functions/calls
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

  override async keyManagerCreate(args: ISphereonKeyManagerCreateArgs): Promise<ManagedKeyInfo> {
    const kms = this.getKmsByName(args.kms)
    const meta: KeyMetadata = { ...args.meta, ...(args.opts && { opts: args.opts }) }
    if (hasKeyOptions(meta) && meta.opts?.ephemeral && !meta.opts.expiration?.removalDate) {
      // Make sure we set a delete date on an ephemeral key
      meta.opts = {
        ...meta.opts,
        expiration: { ...meta.opts?.expiration, removalDate: new Date(Date.now() + 5 * 60 * 1000) },
      }
    }
    const partialKey = await kms.createKey({ type: args.type, meta })
    const key: IKey = { ...partialKey, kms: args.kms }
    key.meta = { ...meta, ...key.meta }
    key.meta.jwkThumbprint = key.meta.jwkThumbprint ?? calculateJwkThumbprintForKey({ key })

    await this.localStore.import(key)
    if (key.privateKeyHex) {
      // Make sure to not export the private key
      delete key.privateKeyHex
    }
    return key
  }

  //FIXME extend the IKeyManagerSignArgs.data to be a string or array of strings

  async keyManagerSign(args: ISphereonKeyManagerSignArgs): Promise<string> {
    const keyInfo: IKey = (await this.localStore.get({ kid: args.keyRef })) as IKey
    const kms = this.getKmsByName(keyInfo.kms)
    if (keyInfo.type === 'Bls12381G2') {
      return await kms.sign({ keyRef: keyInfo, data: Uint8Array.from(Buffer.from(args.data)) })
    }
    // @ts-ignore // we can pass in uint8arrays as well, which the super also can handle but does not expose in its types
    return await super.keyManagerSign(args)
  }

  async keyManagerVerify(args: ISphereonKeyManagerVerifyArgs): Promise<boolean> {
    const kms = this.getKmsByName(args.kms)
    if ('verify' in kms && typeof kms.verify === 'function') {
      // @ts-ignore
      return await kms.verify(args)
    }
    throw Error(`KMS ${kms} does not support verification`)
  }

  async keyManagerListKeys(): Promise<ManagedKeyInfo[]> {
    return this.localStore.list({})
  }

  async keyManagerHandleExpirations(args: ISphereonKeyManagerHandleExpirationsArgs): Promise<Array<ManagedKeyInfo>> {
    const keys = await this.keyManagerListKeys()
    const expiredKeys = keys
      .filter((key) => hasKeyOptions(key.meta))
      .filter((key) => {
        if (hasKeyOptions(key.meta) && key.meta?.opts?.expiration) {
          const expiration = key.meta.opts.expiration
          return !(expiration.expiryDate && expiration.expiryDate.getMilliseconds() > Date.now())
        }
        return false
      })
    if (args.skipRemovals !== true) {
      await Promise.all(expiredKeys.map((key) => this.keyManagerDelete({ kid: key.kid })))
    }
    return keys
  }

  private getKmsByName(name: string): AbstractKeyManagementSystem {
    const kms = this.availableKMSes[name]
    if (!kms) {
      throw Error(`invalid_argument: This agent has no registered KeyManagementSystem with name='${name}'`)
    }
    return kms
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
