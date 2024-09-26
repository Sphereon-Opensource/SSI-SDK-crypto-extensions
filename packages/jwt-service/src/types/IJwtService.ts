import {
  ExternalIdentifierDidOpts,
  ExternalIdentifierResult,
  ExternalIdentifierX5cOpts,
  IIdentifierResolution,
  ManagedIdentifierOptsOrResult,
  ManagedIdentifierResult,
} from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { ClientIdScheme } from '@sphereon/ssi-sdk-ext.x509-utils'
import { IValidationResult, JoseSignatureAlgorithm, JoseSignatureAlgorithmString, JWK } from '@sphereon/ssi-types'
import { IAgentContext, IKeyManager, IPluginMethodMap } from '@veramo/core'

export type IRequiredContext = IAgentContext<IIdentifierResolution & IKeyManager> // could we still interop with Veramo?

export const jwtServiceContextMethods: Array<string> = [
  'jwtPrepareJws',
  'jwtCreateJwsJsonGeneralSignature',
  'jwtCreateJwsJsonFlattenedSignature',
  'jwtCreateJwsCompactSignature',
  'jwtVerifyJwsSignature',
]

export interface IJwtService extends IPluginMethodMap {
  jwtPrepareJws(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<PreparedJwsObject>

  jwtCreateJwsJsonGeneralSignature(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<JwsJsonGeneral>

  jwtCreateJwsJsonFlattenedSignature(args: CreateJwsFlattenedArgs, context: IRequiredContext): Promise<JwsJsonFlattened>

  jwtCreateJwsCompactSignature(args: CreateJwsCompactArgs, context: IRequiredContext): Promise<JwsCompactResult>

  jwtVerifyJwsSignature(args: VerifyJwsArgs, context: IRequiredContext): Promise<IJwsValidationResult>

  // TODO: JWE/encryption
}

export type IJwsValidationResult = IValidationResult & {
  jws: JwsJsonGeneralWithIdentifiers // We always translate to general as that is the most flexible format allowing multiple sigs
}

export interface PreparedJws {
  protectedHeader: JwtHeader
  payload: Uint8Array
  unprotectedHeader?: JwtHeader // only for jws json and also then optional
  existingSignatures?: Array<JwsJsonSignature> // only for jws json and also then optional
}

export interface JwsJsonSignature {
  protected: string
  header?: JwtHeader
  signature: string
}

export type Jws = JwsCompact | JwsJsonFlattened | JwsJsonGeneral

export type JwsCompact = string

export interface JwsJsonFlattened {
  payload: string
  protected: string
  header?: JwtHeader
  signature: string
}

export interface JwsJsonGeneral {
  payload: string
  signatures: Array<JwsJsonSignature>
}

export interface JwsJsonGeneralWithIdentifiers extends JwsJsonGeneral {
  signatures: Array<JwsJsonSignatureWithIdentifier>
}

export interface JwsJsonSignatureWithIdentifier extends JwsJsonSignature {
  identifier: ExternalIdentifierResult
}

export interface PreparedJwsObject {
  jws: PreparedJws
  b64: { payload: string; protectedHeader: string } // header is always json, as it can only be used in JwsJson
  identifier: ManagedIdentifierResult
}

export interface BaseJwtHeader {
  typ?: string
  alg?: string
  kid?: string
}

export interface BaseJwtPayload {
  iss?: string
  sub?: string
  aud?: string[] | string
  exp?: number
  nbf?: number
  iat?: number
  jti?: string
}

export interface JwtHeader extends BaseJwtHeader {
  kid?: string
  jwk?: JWK
  x5c?: string[]

  [key: string]: unknown
}

export interface JwtPayload extends BaseJwtPayload {
  [key: string]: unknown
}

export interface JwsHeaderOpts {
  alg: JoseSignatureAlgorithm | JoseSignatureAlgorithmString
}

export type JwsIdentifierMode = 'x5c' | 'kid' | 'jwk' | 'did' | 'auto'

export type CreateJwsArgs = {
  mode?: JwsIdentifierMode
  issuer: ManagedIdentifierOptsOrResult & {
    noIssPayloadUpdate?: boolean
    noIdentifierInHeader?: boolean
  }
  clientId?: string
  clientIdScheme?: ClientIdScheme | 'did' | string
  protectedHeader: JwtHeader
  payload: JwtPayload | Uint8Array | string
}

export type CreateJwsCompactArgs = CreateJwsArgs

export type CreateJwsFlattenedArgs = Exclude<CreateJwsJsonArgs, 'existingSignatures'>

export type VerifyJwsArgs = {
  jws: Jws
  jwk?: JWK // Jwk will be resolved from jws, but you can also provide one
  opts?: { x5c?: Omit<ExternalIdentifierX5cOpts, 'identifier'>; did?: Omit<ExternalIdentifierDidOpts, 'identifier'> }
}

/**
 * @public
 */
export type CreateJwsJsonArgs = CreateJwsArgs & {
  unprotectedHeader?: JwtHeader // only for jws json
  existingSignatures?: Array<JwsJsonSignature> // Only for jws json
}

/**
 * @public
 */
export interface JwsCompactResult {
  jwt: JwsCompact
}

export function isJwsCompact(jws: Jws): jws is JwsCompact {
  return typeof jws === 'string' && jws.split('~')[0].match(COMPACT_JWS_REGEX) !== null
}

export function isJwsJsonFlattened(jws: Jws): jws is JwsJsonFlattened {
  return typeof jws === 'object' && 'signature' in jws && 'protected' in jws
}

export function isJwsJsonGeneral(jws: Jws): jws is JwsJsonGeneral {
  return typeof jws === 'object' && 'signatures' in jws
}

export const COMPACT_JWS_REGEX = /^([a-zA-Z0-9_=-]+).([a-zA-Z0-9_=-]+)?.([a-zA-Z0-9_=-]+)?$/
