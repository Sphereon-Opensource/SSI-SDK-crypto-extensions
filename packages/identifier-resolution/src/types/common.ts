import { JWK } from '@sphereon/ssi-sdk-ext.key-utils'
import { IIdentifier } from '@veramo/core'
import { ExternalIdentifierType } from './externalIdentifierTypes'
import { ManagedIdentifierType } from './managedIdentifierTypes'

export interface JwkInfo {
  jwk: JWK
  jwkThumbprint: string
}

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
