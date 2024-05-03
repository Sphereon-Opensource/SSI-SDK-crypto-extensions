import { IPluginMethodMap, KeyMetadata, MinimalImportableKey, TKeyType, IKeyManagerSignArgs, IKeyManager } from '@veramo/core'
import { ManagedKeyInfo } from '@veramo/core'

export type PartialKey = ManagedKeyInfo & { privateKeyHex: string }

export interface ISphereonKeyManager extends IKeyManager, IPluginMethodMap {
  keyManagerCreate(args: IKeyManagerCreateArgs): Promise<PartialKey>

  keyManagerImport(key: MinimalImportableKey): Promise<PartialKey>

  keyManagerSign(args: ISphereonKeyManagerSignArgs): Promise<string>

  /**
   * Verifies a signature using the key
   *
   * Does not exist in IKeyManager
   * @param args
   */
  keyManagerVerify(args: ISphereonKeyManagerVerifyArgs): Promise<boolean>

  keyManagerListKeys(): Promise<Array<ManagedKeyInfo>>
}

/**
 * Input arguments for {@link ISphereonKeyManager.keyManagerCreate | keyManagerCreate}
 * @public
 */
export interface IKeyManagerCreateArgs {
  /**
   * Key type
   */
  type: TKeyType

  /**
   * Key Management System
   */
  kms: string

  /**
   * Optional. Key meta data
   */
  meta?: KeyMetadata
}

/**
 * Input arguments for {@link ISphereonKeyManager.keyManagerGet | keyManagerGet}
 * @public
 */
export interface IKeyManagerGetArgs {
  /**
   * Key ID
   */
  kid: string
}

/**
 * Input arguments for {@link ISphereonKeyManager.keyManagerDelete | keyManagerDelete}
 * @public
 */
export interface IKeyManagerDeleteArgs {
  /**
   * Key ID
   */
  kid: string
}

/**
 * Input arguments for {@link ISphereonKeyManagerSignArgs.keyManagerSign | keyManagerSign}
 * @public
 */
// @ts-ignore
export interface ISphereonKeyManagerSignArgs extends IKeyManagerSignArgs {
  /**
   * Data to sign
   */
  data: string | Uint8Array
}

export interface ISphereonKeyManagerVerifyArgs {
  kms: string
  publicKeyHex: string
  type: TKeyType
  algorithm?: string
  data: Uint8Array
  signature: string
}
