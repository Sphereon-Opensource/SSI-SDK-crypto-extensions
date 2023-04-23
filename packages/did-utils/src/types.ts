import { JWTVerifyOptions } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import { DIDDocumentSection, IIdentifier } from '@veramo/core'

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

export const DID_PREFIX = 'did:'
