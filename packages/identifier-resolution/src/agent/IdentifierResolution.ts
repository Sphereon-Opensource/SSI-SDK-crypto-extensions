import { IAgentContext, IAgentPlugin, IDIDManager, IKeyManager } from '@veramo/core'
import { schema } from '..'
import { resolveExternalIdentifier, ensureManagedIdentifierResult } from '../functions'
import {
  ExternalIdentifierDidOpts,
  ExternalIdentifierDidResult,
  ExternalIdentifierOpts,
  ExternalIdentifierResult,
  ExternalIdentifierX5cOpts,
  ExternalIdentifierX5cResult,
  ExternalIdentifierCoseKeyOpts,
  ExternalIdentifierCoseKeyResult,
  ExternalIdentifierJwkOpts,
  ExternalIdentifierJwkResult,
  IIdentifierResolution,
  ManagedIdentifierCoseKeyOpts,
  ManagedIdentifierCoseKeyResult,
  ManagedIdentifierDidOpts,
  ManagedIdentifierDidResult,
  ManagedIdentifierJwkOpts,
  ManagedIdentifierJwkResult,
  ManagedIdentifierKidOpts,
  ManagedIdentifierKidResult,
  ManagedIdentifierResult,
  ManagedIdentifierX5cOpts,
  ManagedIdentifierX5cResult,
  ManagedIdentifierOID4VCIssuerResult,
  ManagedIdentifierKeyOpts,
  ManagedIdentifierKeyResult,
  ManagedIdentifierOptsOrResult,
  ManagedIdentifierOID4VCIssuerOpts
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
    identifierManagedGetByKey: this.identifierGetManagedByKey.bind(this),
    identifierManagedGetByCoseKey: this.identifierGetManagedByCoseKey.bind(this),
    identifierManagedGetByOID4VCIssuer: this.identifierGetManagedByOID4VCIssuer.bind(this),

    identifierExternalResolve: this.identifierResolveExternal.bind(this),
    identifierExternalResolveByDid: this.identifierExternalResolveByDid.bind(this),
    identifierExternalResolveByX5c: this.identifierExternalResolveByX5c.bind(this),
    identifierExternalResolveByJwk: this.identifierExternalResolveByJwk.bind(this),
    identifierExternalResolveByCoseKey: this.identifierExternalResolveByCoseKey.bind(this),

    // todo: JWKSet, oidc-discovery, oid4vci-issuer etc. Anything we already can resolve and need keys of
  }

  /**
   * TODO: Add a cache, as we are retrieving the same keys/info quite often
   */
  constructor(opts?: { crypto?: Crypto }) {
    this._crypto = opts?.crypto ?? global.crypto
  }

  /**
   * Main method for managed identifiers. We always go through this method (also the other methods below) as we want to
   * integrate a plugin for anomaly detection. Having a single method helps
   * @param args
   * @param context
   * @private
   */
  private async identifierGetManaged(
    args: ManagedIdentifierOptsOrResult,
    context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierResult> {
    return await ensureManagedIdentifierResult({ ...args, crypto: this._crypto }, context)
  }

  private async identifierGetManagedByDid(
    args: ManagedIdentifierDidOpts,
    context: IAgentContext<IKeyManager & IDIDManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierDidResult> {
    return (await this.identifierGetManaged({ ...args, method: 'did' }, context)) as ManagedIdentifierDidResult
  }

  private async identifierGetManagedByKid(
    args: ManagedIdentifierKidOpts,
    context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierKidResult> {
    return (await this.identifierGetManaged({ ...args, method: 'kid' }, context)) as ManagedIdentifierKidResult
  }

  private async identifierGetManagedByKey(
    args: ManagedIdentifierKeyOpts,
    context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierKeyResult> {
    return (await this.identifierGetManaged({ ...args, method: 'key' }, context)) as ManagedIdentifierKeyResult
  }

  private async identifierGetManagedByCoseKey(
    args: ManagedIdentifierCoseKeyOpts,
    context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierCoseKeyResult> {
    return (await this.identifierGetManaged({ ...args, method: 'cose_key' }, context)) as ManagedIdentifierCoseKeyResult
  }

  private async identifierGetManagedByOID4VCIssuer(
      args: ManagedIdentifierOID4VCIssuerOpts,
      context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierOID4VCIssuerResult> {
    return (await this.identifierGetManaged({ ...args, method: 'oid4vci-issuer' }, context)) as ManagedIdentifierOID4VCIssuerResult
  }

  private async identifierGetManagedByJwk(
      args: ManagedIdentifierJwkOpts,
      context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierJwkResult> {
    return (await this.identifierGetManaged({ ...args, method: 'jwk' }, context)) as ManagedIdentifierJwkResult
  }

  private async identifierGetManagedByX5c(
    args: ManagedIdentifierX5cOpts,
    context: IAgentContext<IKeyManager & IIdentifierResolution>
  ): Promise<ManagedIdentifierX5cResult> {
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

  private async identifierExternalResolveByCoseKey(
    args: ExternalIdentifierCoseKeyOpts,
    context: IAgentContext<any>
  ): Promise<ExternalIdentifierCoseKeyResult> {
    return (await this.identifierResolveExternal({ ...args, method: 'cose_key' }, context)) as ExternalIdentifierCoseKeyResult
  }
  private async identifierExternalResolveByJwk(args: ExternalIdentifierJwkOpts, context: IAgentContext<any>): Promise<ExternalIdentifierJwkResult> {
    return (await this.identifierResolveExternal({ ...args, method: 'jwk' }, context)) as ExternalIdentifierJwkResult
  }
}
