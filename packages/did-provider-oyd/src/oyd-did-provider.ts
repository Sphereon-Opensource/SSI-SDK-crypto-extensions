import { IIdentifier, IKey, IService, IAgentContext, IKeyManager } from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import type { OydCreateIdentifierOptions, OydDidHoldKeysArgs, OydDidSupportedKeyTypes, CMSMOpts, OydConstructorOptions } from './types/oyd-provider-types.js'
import fetch from 'cross-fetch'

import Debug from 'debug'
const debug = Debug('veramo:oyd-did:identifier-provider')

type IContext = IAgentContext<IKeyManager>

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:oyd` identifiers
 * @public
 */
export class OydDIDProvider extends AbstractIdentifierProvider {
  private defaultKms?: string;
  private cmsmOptions?: CMSMOpts;

  constructor(options?: OydConstructorOptions) {
    super()
    this.defaultKms = options?.defaultKms || "";
    this.cmsmOptions = options?.clientManagedSecretMode || undefined;
  }

  async createIdentifier(
    { kms, options }: { kms?: string; options: OydCreateIdentifierOptions },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if(this.cmsmOptions) return this.createIdentifierWithCMSM({ kms, options }, context);

    const body = { options };
    const url = 'https://oydid-registrar.data-container.net/1.0/createIdentifier';

    let didDoc: any | undefined;
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error('Network response was not ok: ' + response.statusText);
      }
      didDoc = await response.json();
    } catch (error) {
      // @ts-ignore
      throw new Error('There has been a problem with the fetch operation: ' + error.toString());
    }

    const keyType: OydDidSupportedKeyTypes = options?.keyType || 'Ed25519';
    const key = await this.holdKeys(
      {
        // @ts-ignore
        kms: kms || this.defaultKms,
        options: {
          keyType,
          kid: didDoc.did + '#key-doc',
          publicKeyHex: didDoc.keys[0].publicKeyHex,
          privateKeyHex: didDoc.keys[0].privateKeyHex,
        },
      },
      context
    );

    const identifier: Omit<IIdentifier, 'provider'> = {
      did: didDoc.did,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
    };
    debug('Created', identifier.did);
    return identifier;
  }

  async createIdentifierWithCMSM(
    { kms, options }: { kms?: string, options: OydCreateIdentifierOptions },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if(!this.cmsmOptions) throw new Error("did:oyd: no cmsm options defined!!");

    const createIdentifier = 'https://oydid-registrar.data-container.net/1.0/createIdentifier';

    const pubKey = this.cmsmOptions?.publicKeyCallback("default", "local"); // "default" is probably not right, TODO!!
    const kid = pubKey.kid;
    const keyType = pubKey.type;

    const body_create = {  // specify the Identifier options for the registar
      "key": kid,
      "options": {
        "cmsm": true,
        "key_type": keyType
      }
    };

    let signValue: any | undefined;  // do the request
    try {
      const response = await fetch(createIdentifier, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body_create),
      });
      if (!response.ok) {
        throw new Error('Network response was not ok: ' + response.statusText);
      }
      signValue = await response.json();
    } catch (error) {
      // @ts-ignore
      throw new Error('There has been a problem with the fetch operation: ' + error.toString());
    }
    
    // we received our value to sign, now we sign it!
    const { sign } = signValue;
    const signature = this.cmsmOptions.signCallback(kid, sign);

    const body_signed = {
      "key": kid,
      "options": {
        "cmsm": true,
        "sig": signature
      }
    };

    Object.assign(body_signed.options, options);

    let didDoc: any | undefined;  // do the request
    try {
      const response = await fetch(createIdentifier, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body_signed),
      });
      if (!response.ok) {
        throw new Error('Network response was not ok: ' + response.statusText);
      }
      didDoc = await response.json();
    } catch (error) {
      // @ts-ignore
      throw new Error('There has been a problem with the fetch operation: ' + error.toString());
    }

    let oydKeyType: OydDidSupportedKeyTypes = "Ed25519";  // make this not static, TODO!!

    const key = await this.holdKeys(
      {
        // @ts-ignore
        kms: kms || this.defaultKms,
        options: {
          keyType: oydKeyType,
          kid: kid,
          publicKeyHex: pubKey.publicKeyHex,
        },
      },
      context
    );

    const identifier: Omit<IIdentifier, 'provider'> = {
      did: didDoc.did,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
    };
    debug('Created', identifier.did);
    return identifier;
  }

  async updateIdentifier(
    args: { did: string; kms?: string | undefined; alias?: string | undefined; options?: any },
    context: IAgentContext<IKeyManager>
  ): Promise<IIdentifier> {
    throw new Error('OydDIDProvider updateIdentifier not supported yet.');
  }

  async deleteIdentifier(identifier: IIdentifier, context: IContext): Promise<boolean> {
    for (const { kid } of identifier.keys) {
      await context.agent.keyManagerDelete({ kid });
    }
    return true;
  }

  async addKey({ identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any }, context: IContext): Promise<any> {
    return { success: true };
  }

  async addService({ identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any }, context: IContext): Promise<any> {
    return { success: true };
  }

  async removeKey(args: { identifier: IIdentifier; kid: string; options?: any }, context: IContext): Promise<any> {
    return { success: true };
  }

  async removeService(args: { identifier: IIdentifier; id: string; options?: any }, context: IContext): Promise<any> {
    return { success: true };
  }

  private async holdKeys(args: OydDidHoldKeysArgs, context: IContext): Promise<IKey> {
    if (args.options.privateKeyHex) {
      return context.agent.keyManagerImport({
        // @ts-ignore
        kms: args.kms || this.defaultKms,
        type: args.options.keyType,
        kid: args.options.kid,
        privateKeyHex: args.options.privateKeyHex,
        meta: {
          algorithms: ['Ed25519'],
        },
      });
    }
    return context.agent.keyManagerCreate({
      type: args.options.keyType,
      // @ts-ignore
      kms: args.kms || this.defaultKms,
      meta: {
        algorithms: ['Ed25519'],
      },
    });
  }
}
