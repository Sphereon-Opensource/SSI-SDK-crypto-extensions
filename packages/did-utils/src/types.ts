import { JWTVerifyOptions } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import { DIDDocumentSection, IIdentifier } from '@veramo/core'
import { TKeyType } from '@sphereon/ssi-sdk-ext.key-utils'

export enum SupportedDidMethodEnum {
  DID_ETHR = 'ethr',
  DID_KEY = 'key',
  DID_LTO = 'lto',
  DID_ION = 'ion',
  DID_EBSI = 'ebsi',
  DID_JWK = 'jwk',
}

export enum IdentifierAliasEnum {
  PRIMARY = 'primary',
}

export enum KeyManagementSystemEnum {
  LOCAL = 'local',
}

export interface ResolveOpts {
  jwtVerifyOpts?: JWTVerifyOptions
  resolver?: Resolvable
  resolveUrl?: string
  noUniversalResolverFallback?: boolean
  subjectSyntaxTypesSupported?: string[]
}

export interface IDIDOptions {
  resolveOpts?: ResolveOpts
  identifierOpts: IIdentifierOpts
  supportedDIDMethods?: string[]
}

export interface IIdentifierOpts {
  identifier: IIdentifier | string
  verificationMethodSection?: DIDDocumentSection
  kid?: string
}

export type IdentifierProviderOpts = {
  type?: TKeyType
  use?: string
  method?: SupportedDidMethodEnum
  [x: string]: any
}

export type CreateIdentifierOpts = {
  method: SupportedDidMethodEnum
  createOpts?: CreateIdentifierCreateOpts
}

export type CreateIdentifierCreateOpts = {
  kms?: KeyManagementSystemEnum
  alias?: string
  options?: IdentifierProviderOpts
}

export type CreateOrGetIdentifierOpts = {
  method: SupportedDidMethodEnum
  createOpts?: CreateIdentifierCreateOpts
}

export const DID_PREFIX = 'did:'

export interface GetOrCreateResult<T> {
  created: boolean
  result: T
}
