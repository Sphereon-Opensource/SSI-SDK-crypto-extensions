import { IAgentContext, IDIDManager, IKeyManager, IPluginMethodMap } from '@veramo/core'
import {
  ExternalIdentifierDidOpts,
  ExternalIdentifierDidResult,
  ExternalIdentifierOpts,
  ExternalIdentifierResult,
  ExternalIdentifierX5cOpts,
  ExternalIdentifierX5cResult,
} from './externalIdentifierTypes'
import {
  ManagedIdentifierDidOpts,
  ManagedIdentifierDidResult,
  ManagedIdentifierJwkOpts,
  ManagedIdentifierJwkResult,
  ManagedIdentifierKeyOpts,
  ManagedIdentifierKeyResult,
  ManagedIdentifierKidOpts,
  ManagedIdentifierKidResult,
  ManagedIdentifierOpts,
  ManagedIdentifierResult,
  ManagedIdentifierX5cOpts,
  ManagedIdentifierX5cResult,
} from './managedIdentifierTypes'

// Exposing the methods here for any REST implementation
export const identifierResolutionContextMethods: Array<string> = [
  'identifierManagedGet',
  'identifierManagedGetByDid',
  'identifierManagedGetByKid',
  'identifierManagedGetByJwk',
  'identifierManagedGetByX5c',
  'identifierManagedGetByKey',
  'identifierExternalResolve',
  'identifierExternalResolveByDid',
  'identifierExternalResolveByX5c',
]

/**
 * @public
 */
export interface IIdentifierResolution extends IPluginMethodMap {
  /**
   * Main method for managed identifiers. We always go through this method (also the others) as we want to integrate a plugin for anomaly detection. Having a single method helps
   *
   * The end result of all these methods is a common baseline response that allows to use a key from the registered KMS systems. It also provides kid and iss(uer) values that can be used in a JWT/JWS for instance
   * @param args
   * @param context
   * @public
   */
  identifierManagedGet(args: ManagedIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierResult>

  identifierManagedGetByDid(args: ManagedIdentifierDidOpts, context: IAgentContext<IKeyManager & IDIDManager>): Promise<ManagedIdentifierDidResult>

  identifierManagedGetByKid(args: ManagedIdentifierKidOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierKidResult>

  identifierManagedGetByJwk(args: ManagedIdentifierJwkOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierJwkResult>

  identifierManagedGetByX5c(args: ManagedIdentifierX5cOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierX5cResult>

  identifierManagedGetByKey(args: ManagedIdentifierKeyOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierKeyResult>

  // TODO: We can create a custom managed identifier method allowing developers to register a callback function to get their implementation hooked up. Needs more investigation as it would also impact the KMS

  /**
   * Main method for external identifiers. We always go through this method (also the others) as we want to integrate a plugin for anomaly detection. Having a single method helps
   * @param args
   * @param context
   * @public
   */
  identifierExternalResolve(args: ExternalIdentifierOpts, context: IAgentContext<any>): Promise<ExternalIdentifierResult>

  identifierExternalResolveByDid(args: ExternalIdentifierDidOpts, context: IAgentContext<any>): Promise<ExternalIdentifierDidResult>

  identifierExternalResolveByX5c(args: ExternalIdentifierX5cOpts, context: IAgentContext<any>): Promise<ExternalIdentifierX5cResult>
}
