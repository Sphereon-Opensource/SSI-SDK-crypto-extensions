import { JWK } from '@sphereon/ssi-sdk-ext.key-utils'
import { DIDDocumentSection, IIdentifier, IKey, TKeyType } from '@veramo/core'
import { isDidIdentifier, isJwkIdentifier, isKidIdentifier, isX5cIdentifier, JwkInfo } from './common'

/**
 * Use whenever we need to pass in an identifier. We can pass in kids, DIDs, IIdentifier objects and x5chains
 *
 * The functions below can be used to check the type, and they also provide the proper runtime types
 */
export type ManagedIdentifierType = IIdentifier /*did*/ | string /*did or kid*/ | string[] /*x5c*/ | JWK

export type ManagedIdentifierOpts = (ManagedIdentifierJwkOpts | ManagedIdentifierX5cOpts | ManagedIdentifierDidOpts | ManagedIdentifierKidOpts) &
  ManagedIdentifierOptsBase

export type ManagedIdentifierOptsBase = {
  method?: ManagedIdentifierMethod // If provided always takes precedences otherwise it will be inferred from the identifier
  identifier: ManagedIdentifierType
  kmsKeyRef?: string
}

export type ManagedIdentifierDidOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'did'
  identifier: IIdentifier | string
  keyType?: TKeyType
  offlineWhenNoDIDRegistered?: boolean
  noVerificationMethodFallback?: boolean
  controllerKey?: boolean
  vmRelationship?: DIDDocumentSection
}

export function isManagedIdentifierDidOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierDidOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'did') || isDidIdentifier(identifier)
}

export type ManagedIdentifierKidOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'kid'
  identifier: string
}

export function isManagedIdentifierKidOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierKidOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'kid') || isKidIdentifier(identifier)
}

export type ManagedIdentifierJwkOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'jwk'
  identifier: JWK
}

export function isManagedIdentifierJwkOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierJwkOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'jwk') || isJwkIdentifier(identifier)
}

export type ManagedIdentifierX5cOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'x5c'
  identifier: string[]
}

export function isManagedIdentifierX5cOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierX5cOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'x5c') || isX5cIdentifier(identifier)
}

export interface ManagedJwkInfo extends JwkInfo {
  kmsKeyRef: string
}

export interface IManagedIdentifierResultBase extends ManagedJwkInfo {
  method: ManagedIdentifierMethod
  key: IKey
}

export function isManagedIdentifierDidResult(object: IManagedIdentifierResultBase): object is ManagedIdentifierDidResult {
  return object!! && typeof object === 'object' && 'method' in object && object.method === 'did'
}

export function isManagedIdentifierX5cResult(object: IManagedIdentifierResultBase): object is ManagedIdentifierDidResult {
  return object!! && typeof object === 'object' && 'method' in object && object.method === 'x5c'
}

export function isManagedIdentifierJwkResult(object: IManagedIdentifierResultBase): object is ManagedIdentifierJwkResult {
  return object!! && typeof object === 'object' && 'method' in object && object.method === 'jwk'
}

export function isManagedIdentifierKidResult(object: IManagedIdentifierResultBase): object is ManagedIdentifierKidResult {
  return object!! && typeof object === 'object' && 'method' in object && object.method === 'kid'
}

export interface ManagedIdentifierDidResult extends IManagedIdentifierResultBase {
  method: 'did'
  identifier: IIdentifier
  did: string
  // key: IKey // The key associated with the requested did method sections. Controller key in case of no DID method section requested
  keys: Array<IKey> // If there is more than one key for the VM relationship.
  verificationMethodSection?: DIDDocumentSection
  controllerKeyId: string
}

export interface ManagedIdentifierJwkResult extends IManagedIdentifierResultBase {
  method: 'jwk'
}

export interface ManagedIdentifierKidResult extends IManagedIdentifierResultBase {
  method: 'kid'
}

export interface ManagedIdentifierX5cResult extends IManagedIdentifierResultBase {
  method: 'x5c'
  x5c: string[]
  certificate: any // Certificate(JSON_, but trips schema generator. Probably want to create our own DTO
}

export type ManagedIdentifierMethod = 'did' | 'jwk' | 'x5c' | 'kid'

export type ManagedIdentifierResult =
  | ManagedIdentifierX5cResult
  | ManagedIdentifierDidResult
  | ManagedIdentifierJwkResult
  | ManagedIdentifierKidResult
