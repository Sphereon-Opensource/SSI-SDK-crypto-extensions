import { DidDocumentJwks } from '@sphereon/ssi-sdk-ext.did-utils'
import { JWK } from '@sphereon/ssi-sdk-ext.key-utils'
import { X509ValidationResult } from '@sphereon/ssi-sdk-ext.x509-utils'
import { IParsedDID } from '@sphereon/ssi-types'
import {
  DIDDocument,
  DIDDocumentSection,
  DIDResolutionResult,
  IAgentContext,
  IDIDManager,
  IIdentifier,
  IKey,
  IKeyManager,
  IPluginMethodMap,
  TKeyType,
} from '@veramo/core'

/**
 * @public
 */
export interface IIdentifierResolution extends IPluginMethodMap {
  identifierManagedGet(args: ManagedIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierResult>

  identifierManagedGetByDid(args: ManagedIdentifierDidOpts, context: IAgentContext<IKeyManager & IDIDManager>): Promise<ManagedIdentifierDidResult>

  identifierManagedGetByKid(args: ManagedIdentifierKidOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierKidResult>

  identifierManagedGetByJwk(args: ManagedIdentifierJwkOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierJwkResult>

  identifierManagedGetByX5c(args: ManagedIdentifierX5cOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierX5cResult>

  identifierExternalResolve(args: ExternalIdentifierOpts, context: IAgentContext<any>): Promise<any>
}

/**
 * Use whenever we need to pass in an identifier. We can pass in kids, DIDs, IIdentifier objects and x5chains
 *
 * The functions below can be used to check the type, and they also provide the proper runtime types
 */
export type ManagedIdentifierType = IIdentifier /*did*/ | string /*did or kid*/ | string[] /*x5c*/ | JWK

/**
 * Use whenever we need to resolve an external identifier. We can pass in kids, DIDs, and x5chains
 *
 * The functions below can be used to check the type, and they also provide the proper runtime types
 */
export type ExternalIdentifierType = string | string[] | JWK

export function isDidIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is IIdentifier | string {
  return isIIdentifier(identifier) || (typeof identifier === 'string' && identifier.startsWith('did:'))
}

export function isIIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is IIdentifier {
  return typeof identifier === 'object' && !Array.isArray(identifier) && 'did' in identifier && 'keys' in identifier
}

export function isJwkIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is JWK {
  return typeof identifier === 'object' && !Array.isArray(identifier) && 'kty' in identifier
}

export function isOidcDiscoveryIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is string {
  return typeof identifier === 'string' && identifier.startsWith('http') && identifier.endsWith('/.well-known/openid-configuration')
}

export function isJwksUrlIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is string {
  return typeof identifier === 'string' && identifier.startsWith('http') && identifier.endsWith('jwks.json')
}

export function isKidIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is string {
  return typeof identifier === 'string' && !identifier.startsWith('did:')
}

export function isX5cIdentifier(identifier: ManagedIdentifierType | ExternalIdentifierType): identifier is string[] {
  return Array.isArray(identifier) && identifier.length > 0 // todo: Do we want to do additional validation? We know it must be DER and thus hex for instance
}

export type ExternalIdentifierOptsBase = {
  method?: ExternalIdentifierMethod // If provided always takes precedences otherwise it will be inferred from the identifier
  identifier: ExternalIdentifierType
}

export type ExternalIdentifierDidOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'did'
  identifier: string
  noVerificationMethodFallback?: boolean
  vmRelationship?: DIDDocumentSection
  localResolution?: boolean // Resolve identifiers hosted by the agent
  uniresolverResolution?: boolean // Resolve identifiers using universal resolver
  resolverResolution?: boolean // Use registered drivers
}

export function isExternalIdentifierDidOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierDidOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'did') || isDidIdentifier(identifier)
}

export type ExternalIdentifierOpts = (ExternalIdentifierJwkOpts | ExternalIdentifierX5cOpts | ExternalIdentifierDidOpts | ExternalIdentifierKidOpts) &
  ExternalIdentifierOptsBase

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

export type ExternalIdentifierKidOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'kid'
  identifier: string
}

export function isExternalIdentifierKidOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierKidOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'kid') || isKidIdentifier(identifier)
}

export type ManagedIdentifierKidOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'kid'
  identifier: string
}

export function isManagedIdentifierKidOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierKidOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'kid') || isKidIdentifier(identifier)
}

export type ExternalIdentifierJwkOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'jwk'
  identifier: JWK
}

export function isExternalIdentifierJwkOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierJwkOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'jwk') || isJwkIdentifier(identifier)
}

export type ExternalIdentifierOidcDiscoveryOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'oidc-discovery'
  identifier: string
}

export function isExternalIdentifierOidcDiscoveryOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierJwkOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'oidc-discovery') || isOidcDiscoveryIdentifier(identifier)
}

export type ExternalIdentifierJwksUrlOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'jwks-url'
  identifier: string
}

export function isExternalIdentifierJwksUrlOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierJwksUrlOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'oidc-discovery') || isJwksUrlIdentifier(identifier)
}

export type ManagedIdentifierJwkOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'jwk'
  identifier: JWK
}

export function isManagedIdentifierJwkOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierJwkOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'jwk') || isJwkIdentifier(identifier)
}

export type ExternalIdentifierX5cOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'x5c'
  identifier: string[]
  verify: boolean
  verificationTime?: Date
  trustAnchors?: string[]
}

export function isExternalIdentifierX5cOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierX5cOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'x5c') || isX5cIdentifier(identifier)
}

export type ManagedIdentifierX5cOpts = Omit<ManagedIdentifierOptsBase, 'method'> & {
  method?: 'x5c'
  identifier: string[]
}

export function isManagedIdentifierX5cOpts(opts: ManagedIdentifierOptsBase): opts is ManagedIdentifierX5cOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'x5c') || isX5cIdentifier(identifier)
}

export type ExternalIdentifierMethod = 'did' | 'jwk' | 'x5c' | 'kid' | 'oidc-discovery' | 'jwks-url' | 'oid4vci-issuer'

export type ExternalIdentifierResult = ExternalIdentifierDidResult | ExternalIdentifierX5cResult

export type ManagedIdentifierMethod = 'did' | 'jwk' | 'x5c' | 'kid'

export type ManagedIdentifierResult =
  | ManagedIdentifierX5cResult
  | ManagedIdentifierDidResult
  | ManagedIdentifierJwkResult
  | ManagedIdentifierKidResult

export interface IExternalIdentifierResultBase {
  method: ExternalIdentifierMethod
  jwks: Array<ExternalJwkInfo>
}

export interface JwkInfo {
  jwk: JWK
  jwkThumbprint: string
}

export interface ExternalJwkInfo extends JwkInfo {
  kid?: string
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

export interface ExternalIdentifierDidResult extends IExternalIdentifierResultBase {
  method: 'did'
  did: string
  didDocument?: DIDDocument
  didJwks?: DidDocumentJwks
  didResolutionResult: Omit<DIDResolutionResult, 'didDocument'> // we already provide that directly
  didParsed: IParsedDID
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

export interface ExternalIdentifierX5cResult extends IExternalIdentifierResultBase {
  method: 'x5c'
  x5c: string[]
  issuerJWK: JWK
  verificationResult?: X509ValidationResult
  certificates: any[] // for now since our schema generator trips on pkijs Certificate(Json) object //fixme
}

export interface ManagedIdentifierX5cResult extends IManagedIdentifierResultBase {
  method: 'x5c'
  x5c: string[]
  certificate: any // Certificate(JSON_, but trips schema generator. Probably want to create our own DTO
}
