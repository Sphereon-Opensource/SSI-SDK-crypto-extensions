import { DidDocumentJwks } from '@sphereon/ssi-sdk-ext.did-utils'
import { JWK } from '@sphereon/ssi-sdk-ext.key-utils'
import { X509ValidationResult } from '@sphereon/ssi-sdk-ext.x509-utils'
import { IParsedDID } from '@sphereon/ssi-types'
import { DIDDocument, DIDDocumentSection, DIDResolutionResult } from '@veramo/core'
import { isDidIdentifier, isJwkIdentifier, isJwksUrlIdentifier, isKidIdentifier, isOidcDiscoveryIdentifier, isX5cIdentifier, JwkInfo } from './common'

/**
 * Use whenever we need to resolve an external identifier. We can pass in kids, DIDs, and x5chains
 *
 * The functions below can be used to check the type, and they also provide the proper runtime types
 */
export type ExternalIdentifierType = string | string[] | JWK

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

export type ExternalIdentifierKidOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'kid'
  identifier: string
}

export function isExternalIdentifierKidOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierKidOpts {
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

export type ExternalIdentifierX5cOpts = Omit<ExternalIdentifierOptsBase, 'method'> & {
  method?: 'x5c'
  identifier: string[]
  verify?: boolean // defaults to true
  verificationTime?: Date
  trustAnchors?: string[]
}

export function isExternalIdentifierX5cOpts(opts: ExternalIdentifierOptsBase): opts is ExternalIdentifierX5cOpts {
  const { identifier } = opts
  return ('method' in opts && opts.method === 'x5c') || isX5cIdentifier(identifier)
}

export type ExternalIdentifierMethod = 'did' | 'jwk' | 'x5c' | 'kid' | 'oidc-discovery' | 'jwks-url' | 'oid4vci-issuer'

export type ExternalIdentifierResult = ExternalIdentifierDidResult | ExternalIdentifierX5cResult

export interface IExternalIdentifierResultBase {
  method: ExternalIdentifierMethod
  jwks: Array<ExternalJwkInfo>
}

export interface ExternalIdentifierX5cResult extends IExternalIdentifierResultBase {
  method: 'x5c'
  x5c: string[]
  issuerJWK: JWK
  verificationResult?: X509ValidationResult
  certificates: any[] // for now since our schema generator trips on pkijs Certificate(Json) object //fixme
}

export interface ExternalJwkInfo extends JwkInfo {
  kid?: string
}

export interface ExternalIdentifierDidResult extends IExternalIdentifierResultBase {
  method: 'did'
  did: string
  didDocument?: DIDDocument
  didJwks?: DidDocumentJwks
  didResolutionResult: Omit<DIDResolutionResult, 'didDocument'> // we already provide that directly
  didParsed: IParsedDID
}