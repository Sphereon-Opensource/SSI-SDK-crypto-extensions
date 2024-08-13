import { IAgentContext, IAgentPlugin, IDIDManager, IKeyManager } from '@veramo/core'
import { schema } from '..'
import { getManagedIdentifier, resolveExternalIdentifier } from '../functions'
import {
  ExternalIdentifierDidOpts,
  ExternalIdentifierDidResult,
  ExternalIdentifierOpts,
  ExternalIdentifierResult,
  ExternalIdentifierX5cOpts,
  ExternalIdentifierX5cResult,
  IIdentifierResolution,
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
} from '../types'

/**
 * @public
 */
export class IdentifierResolution implements IAgentPlugin {
  private readonly _crypto: Crypto

  readonly schema = schema.IMnemonicInfoGenerator
  readonly methods: IIdentifierResolution = {
    identifierManagedGet: this.identifierGetManaged.bind(this),
    identifierManagedGetByDid: this.identifierGetManagedByDid.bind(this),
    identifierManagedGetByKid: this.identifierGetManagedByKid.bind(this),
    identifierManagedGetByJwk: this.identifierGetManagedByJwk.bind(this),
    identifierManagedGetByX5c: this.identifierGetManagedByX5c.bind(this),

    identifierExternalResolve: this.identifierResolveExternal.bind(this),
    identifierExternalResolveByDid: this.identifierExternalResolveByDid.bind(this),
    identifierExternalResolveByX5c: this.identifierExternalResolveByX5c.bind(this),

    // todo: JWKSet, oidc-discovery, oid4vci-issuer etc. Anything we already can resolve and need keys of
  }

  /**
   * TODO: Add a cache, as we are retrieving the same keys/info quite often
   */
  constructor({ crypto: cryptoArg }: { crypto: Crypto }) {
    this._crypto = cryptoArg ?? global.crypto
  }

  /**
   * Main method for managed identifiers. We always go through this method (also the others) as we want to integrate a plugin for anomaly detection. Having a single method helps
   * @param args
   * @param context
   * @private
   */
  private async identifierGetManaged(args: ManagedIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierResult> {
    return await getManagedIdentifier({ ...args, crypto: this._crypto }, context)
  }

  private async identifierGetManagedByDid(
    args: ManagedIdentifierDidOpts,
    context: IAgentContext<IKeyManager & IDIDManager>
  ): Promise<ManagedIdentifierDidResult> {
    return (await this.identifierGetManaged({ ...args, method: 'did' }, context)) as ManagedIdentifierDidResult
  }

  private async identifierGetManagedByKid(args: ManagedIdentifierKidOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierKidResult> {
    return (await this.identifierGetManaged({ ...args, method: 'kid' }, context)) as ManagedIdentifierKidResult
  }

  private async identifierGetManagedByJwk(args: ManagedIdentifierJwkOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierJwkResult> {
    return (await this.identifierGetManaged({ ...args, method: 'jwk' }, context)) as ManagedIdentifierJwkResult
  }

  private async identifierGetManagedByX5c(args: ManagedIdentifierX5cOpts, context: IAgentContext<IKeyManager>): Promise<ManagedIdentifierX5cResult> {
    return (await this.identifierGetManaged({ ...args, method: 'x5c' }, context)) as ManagedIdentifierX5cResult
  }

  private async identifierResolveExternal(args: ExternalIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<ExternalIdentifierResult> {
    return await resolveExternalIdentifier({ ...args, crypto: this._crypto }, context)
  }

  private async identifierExternalResolveByDid(args: ExternalIdentifierDidOpts, context: IAgentContext<any>): Promise<ExternalIdentifierDidResult> {
    return (await this.identifierResolveExternal({ ...args, method: 'did' }, context)) as ExternalIdentifierDidResult
  }

  private async identifierExternalResolveByX5c(args: ExternalIdentifierX5cOpts, context: IAgentContext<any>): Promise<ExternalIdentifierX5cResult> {
    return (await this.identifierResolveExternal({ ...args, method: 'x5c' }, context)) as ExternalIdentifierX5cResult
  }
}
