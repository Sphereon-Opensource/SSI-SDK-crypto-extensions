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
  ManagedIdentifierKidOpts,
  ManagedIdentifierKidResult,
  ManagedIdentifierOpts,
  ManagedIdentifierResult,
  ManagedIdentifierX5cOpts,
  ManagedIdentifierX5cResult,
} from './managedIdentifierTypes'

/**
 * @public
 */
export interface IIdentifierResolution extends IPluginMethodMap {
  /**
   * Main method for managed identifiers. We always go through this method (also the others) as we want to integrate a plugin for anomaly detection. Having a single method helps
   * @param args
   * @param context
   * @public
   */
  identifierManagedGet(args: ManagedIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierResult>

  identifierManagedGetByDid(args: ManagedIdentifierDidOpts, context: IAgentContext<IKeyManager & IDIDManager>): Promise<ManagedIdentifierDidResult>

  identifierManagedGetByKid(args: ManagedIdentifierKidOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierKidResult>

  identifierManagedGetByJwk(args: ManagedIdentifierJwkOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierJwkResult>

  identifierManagedGetByX5c(args: ManagedIdentifierX5cOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierX5cResult>

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
