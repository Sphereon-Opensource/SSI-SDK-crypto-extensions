import { JWTHeader, JWTPayload, JWTVerifyOptions } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import { DIDDocumentSection, IAgentContext, IDIDManager, IIdentifier, IKeyManager, IResolver } from '@veramo/core'
import { TKeyType } from '@sphereon/ssi-sdk-ext.key-utils'
import {IdentifierType} from "./did-functions";

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
  type: IdentifierType
  identifier: IIdentifier | string
  didOpts?: {
    keyType?: TKeyType
    offlineWhenNoDIDRegistered?: boolean
    noVerificationMethodFallback?: boolean
    controllerKey?: boolean
    vmRelationship: DIDDocumentSection
  }
  kmsKeyRef?: string
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

export type SignJwtArgs = {
  idOpts: IIdentifierOpts
  header: Partial<JWTHeader>
  payload: Partial<JWTPayload>
  options: { issuer: string; expiresIn?: number; canonicalize?: boolean }
  context: IRequiredSignAgentContext
}

export type GetSignerArgs = {
  idOpts: IIdentifierOpts
  context: IRequiredSignAgentContext
}

export type IRequiredSignAgentContext = IAgentContext<IKeyManager & IDIDManager & IResolver>
