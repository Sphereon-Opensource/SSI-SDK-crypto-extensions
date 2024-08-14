import {
  IIdentifierResolution,
  ManagedIdentifierOpts,
  ManagedIdentifierResult
} from '@sphereon/ssi-sdk-ext.identifier-resolution'
import {ISphereonKeyManager} from '@sphereon/ssi-sdk-ext.key-manager'
import {JWK, SignatureAlgorithmJwa} from '@sphereon/ssi-sdk-ext.key-utils'
import {IAgentContext, IPluginMethodMap} from '@veramo/core'

export type IRequiredContext = IAgentContext<IIdentifierResolution & ISphereonKeyManager> // could we still interop with Veramo?
export interface IJwtService extends IPluginMethodMap {
  jwtPrepareJws(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<PreparedJwsObject>

  jwtCreateJwsJsonGeneralSignature(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<JwsJsonGeneral>

  jwtCreateJwsJsonFlattenedSignature(args: CreateJwsFlattenedArgs, context: IRequiredContext): Promise<JwsJsonFlattened>

  jwtCreateJwsCompactSignature(args: CreateJwsCompactArgs, context: IRequiredContext): Promise<JwsCompactResult>

  // jwtVerifyJwsCompactSignature(args: {jwt: string}): Promise<any>

  // TODO: JWE/encryption
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

export interface PreparedJwsObject {
  jws: PreparedJws
  b64: { payload: string; protectedHeader: string } // header is always json, as it can only be used in JwsJson
  issuer: ManagedIdentifierOpts
  identifier: ManagedIdentifierResult
}

export interface BaseJwtHeader {
  typ?: string;
  alg?: string;
  kid?: string;
}
export interface BaseJwtPayload {
  iss?: string;
  sub?: string;
  aud?: string[] | string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
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
  als: SignatureAlgorithmJwa
}

export type CreateJwsMode = 'x5c' | 'kid' | 'jwk' | 'did' | 'auto'

export type CreateJwsArgs = {
  mode?: CreateJwsMode
  issuer: ManagedIdentifierOpts & { noIssPayloadUpdate?: boolean, noIdentifierInHeader?: boolean }
  protectedHeader: JwtHeader
  payload: JwtPayload | Uint8Array | string
}

export type CreateJwsCompactArgs = CreateJwsArgs

export type CreateJwsFlattenedArgs = Exclude<CreateJwsJsonArgs, 'existingSignatures'>

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
  jwt: JwsCompact;
}

// export const COMPACT_JWS_REGEX = /^([a-zA-Z0-9_=-]+)\.([a-zA-Z0-9_=-]+)?\.([a-zA-Z0-9_=-]+)$/
