import { IAgentContext, IAgentPlugin, IDIDManager, IKeyManager } from '@veramo/core'
import { getManagedIdentifier } from '../functions'

import {
  ManagedIdentifierResult,
  ManagedIdentifierDidOpts,
  ManagedIdentifierDidResult,
  ManagedIdentifierJwkOpts,
  ManagedIdentifierJwkResult,
  ManagedIdentifierKidOpts,
  ManagedIdentifierKidResult,
  ManagedIdentifierOpts,
  ManagedIdentifierX5cOpts,
  ManagedIdentifierX5cResult,
  schema,
} from '../index'
import { ExternalIdentifierOpts, IIdentifierResolution } from '../types/IIdentifierResolution'

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
  }

  /**
   * TODO: Add a cache, as we are retrieving the same keys/info quite often
   */
  constructor({ crypto: cryptoArg }: { crypto: Crypto }) {
    this._crypto = cryptoArg ?? global.crypto
  }

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

  private async identifierResolveExternal(args: ExternalIdentifierOpts, context: IAgentContext<IKeyManager>): Promise<any> {
    return await getManagedIdentifier({ ...args, crypto: this._crypto }, context)
  }
}
