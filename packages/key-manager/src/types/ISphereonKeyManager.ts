import { IPluginMethodMap, IKey, KeyMetadata, MinimalImportableKey, TKeyType, IKeyManagerSignArgs } from '@veramo/core'

export type PartialKey = Partial<IKey>

export interface ISphereonKeyManager extends IPluginMethodMap {
  keyManagerCreate(args: IKeyManagerCreateArgs): Promise<PartialKey>

  keyManagerGetKeyManagementSystems(): Promise<Array<string>>

  keyManagerGet({ kid }: IKeyManagerGetArgs): Promise<IKey>

  keyManagerDelete({ kid }: IKeyManagerDeleteArgs): Promise<boolean>

  keyManagerImport(key: MinimalImportableKey): Promise<PartialKey>

  keyManagerSign(args: ISphereonKeyManagerSignArgs): Promise<string>

  keyManagerVerify(args: ISphereonKeyManagerVerifyArgs): Promise<boolean>
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
