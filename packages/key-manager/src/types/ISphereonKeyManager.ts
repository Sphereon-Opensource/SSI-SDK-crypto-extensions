import { IPluginMethodMap, IKey, KeyMetadata, MinimalImportableKey, TKeyType } from '@veramo/core'

export type PartialKey = Partial<IKey>

export interface ISphereonKeyManager extends IPluginMethodMap {
  keyManagerCreate(args: IKeyManagerCreateArgs): Promise<PartialKey>
  keyManagerGetKeyManagementSystems(): Promise<Array<string>>
  keyManagerGet({ kid }: IKeyManagerGetArgs): Promise<IKey>
  keyManagerDelete({ kid }: IKeyManagerDeleteArgs): Promise<boolean>
  keyManagerImport(key: MinimalImportableKey): Promise<PartialKey>
  keyManagerSign(args: IKeyManagerSignArgs): Promise<string>
  keyManagerVerify(args: IKeyManagerVerifyArgs): Promise<boolean>
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
 * Input arguments for {@link ISphereonKeyManager.keyManagerSign | keyManagerSign}
 * @public
 */
export interface IKeyManagerSignArgs {
  /**
   * The key handle, as returned during `keyManagerCreateKey`
   */
  keyRef: string

  /**
   * Data to sign
   */
  data: Uint8Array[]
}

export interface IKeyManagerVerifyArgs {
  kms: string
  publicKey: Uint8Array
  messages: Uint8Array[]
  signature: Uint8Array
}
