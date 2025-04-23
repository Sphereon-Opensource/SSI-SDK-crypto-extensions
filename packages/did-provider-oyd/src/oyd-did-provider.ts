import { IIdentifier, IKey, IService, IAgentContext, IKeyManager, TKeyType } from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { KeyManager } from '@veramo/key-manager'
import type {
  OydCreateIdentifierOptions,
  OydDidHoldKeysArgs,
  OydDidSupportedKeyTypes,
  CMSMCallbackOpts,
  OydConstructorOptions,
} from './types/oyd-provider-types.js'
import fetch from 'cross-fetch'

import Debug from 'debug'

const debug = Debug('veramo:oyd-did:identifier-provider')
const OYDID_REGISTRAR_URL = 'https://oydid-registrar.data-container.net/1.0/createIdentifier'

type IContext = IAgentContext<IKeyManager>

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:oyd` identifiers
 * @public
 */
export class OydDIDProvider extends AbstractIdentifierProvider {
  private readonly defaultKms?: string
  private readonly cmsmCallbackOpts?: CMSMCallbackOpts

  constructor(options?: OydConstructorOptions) {
    super()
    this.defaultKms = options?.defaultKms
    this.cmsmCallbackOpts = options?.clientManagedSecretMode
  }

  private async assertedKms(...kms: (string | undefined)[]): Promise<string> {
    if (!kms || kms.length === 0) {
      return Promise.reject(Error('KMS must be provided either as a parameter or via defaultKms.'))
    }
    const result = kms.find((k) => !!k)
    if (!result) {
      return Promise.reject(Error('KMS must be provided either as a parameter or via defaultKms.'))
    }
    return result
  }

  async createIdentifier(
    { kms, options }: { kms?: string; options: OydCreateIdentifierOptions },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const resolvedKms = await this.assertedKms(kms, this.defaultKms)

    if ((this.cmsmCallbackOpts && !options.cmsm) || (options.cmsm && options.cmsm.enabled !== false)) {
      if (!this.cmsmCallbackOpts) {
        return Promise.reject(Error('did:oyd: no cmsm options defined on oyd did provider, but cmsm was enabled on the call!'))
      }
      return await this.createIdentifierWithCMSM({ kms: resolvedKms, options }, context)
    }

    const body = { options }
    let didDoc: any | undefined
    try {
      const response = await fetch(OYDID_REGISTRAR_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        debug('Error response from OydDID Registrar: ', response)
        return Promise.reject(Error('Network response was not ok: ' + response.statusText))
      }
      didDoc = await response.json()
    } catch (error: any) {
      debug('Unexpected error from OydDID Registrar: ', error)
      return Promise.reject(Error('There has been a problem with the fetch operation: ' + error.toString()))
    }

    const keyType: OydDidSupportedKeyTypes = options?.keyType ?? 'Secp256r1'
    const key = await this.importOrCreateKey(
      {
        kms: resolvedKms,
        options: {
          keyType,
          kid: didDoc.did + '#key-doc',
          publicKeyHex: didDoc.keys[0].publicKeyHex,
          privateKeyHex: didDoc.keys[0].privateKeyHex,
        },
      },
      context
    )

    const identifier: Omit<IIdentifier, 'provider'> = {
      did: didDoc.did,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
    }
    debug('Created', identifier.did)
    return identifier
  }

  async createIdentifierWithCMSM(
    { kms, options }: { kms?: string; options: OydCreateIdentifierOptions },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const cmsmCallbackOpts = this.cmsmCallbackOpts
    if (!cmsmCallbackOpts) {
      return Promise.reject(Error('did:oyd: no cmsm options defined!'))
    }

    const assertedKms = await this.assertedKms(kms, this.defaultKms)
    const pubKey = options.key ?? (await cmsmCallbackOpts.publicKeyCallback(options.kid ?? 'default', assertedKms, options.cmsm?.create !== false, options.keyType)) // "default" is probably not right, TODO!!
    const kid = pubKey.kid
    const keyType = pubKey.type

    let signValue: any | undefined // do the request
    try {
      const body_create = {
        // specify the Identifier options for the registrar
        key: kid,
        options: {
          cmsm: true,
          key_type: keyType,
        },
      }
      const response = await fetch(OYDID_REGISTRAR_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body_create),
      })
      if (!response.ok) {
        debug('Error response from OydDID Registrar: ', body_create, response)
        return Promise.reject(Error('Network response was not ok: ' + response.statusText))
      }
      signValue = await response.json()
    } catch (error: any) {
      debug('Unexpected error from OydDID Registrar: ', error)
      return Promise.reject(Error('There has been a problem with the fetch operation: ' + error.toString()))
    }

    // we received our value to sign, now we sign it!
    const { sign } = signValue
    const signature = await cmsmCallbackOpts.signCallback(kid, sign)

    const body_signed = {
      key: kid,
      options: {
        cmsm: true,
        sig: signature,
      },
    }

    Object.assign(body_signed.options, options)

    let didDoc: any | undefined // do the request
    try {
      const response = await fetch(OYDID_REGISTRAR_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body_signed),
      })
      if (!response.ok) {
        debug('Error response from OydDID Registrar: ', response)
        return Promise.reject(Error('Network response was not ok: ' + response.statusText))
      }
      didDoc = await response.json()
    } catch (error: any) {
      debug('Unexpected error from OydDID Registrar: ', error)
      return Promise.reject(Error('There has been a problem with the fetch operation: ' + error.toString()))
    }

    /*    let oydKeyType: OydDidSupportedKeyTypes = "Secp256r1";

        const key = await this.holdKeys(
          {
            kms: assertedKms,
            options: {
              keyType: oydKeyType,
              kid: kid,
              publicKeyHex: pubKey.publicKeyHex,
            },
          },
          context
        );*/

    const identifier: Omit<IIdentifier, 'provider'> = {
      did: didDoc.did,
      controllerKeyId: pubKey.kid,
      keys: [pubKey],
      services: [],
    }
    debug('Created', identifier.did)
    return identifier
  }

  async updateIdentifier(
    args: { did: string; kms?: string | undefined; alias?: string | undefined; options?: any },
    context: IAgentContext<IKeyManager>
  ): Promise<IIdentifier> {
    throw new Error('OydDIDProvider updateIdentifier not supported yet.')
  }

  async deleteIdentifier(identifier: IIdentifier, context: IContext): Promise<boolean> {
    for (const { kid } of identifier.keys) {
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey({ identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any }, context: IContext): Promise<any> {
    return { success: true }
  }

  async addService({ identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any }, context: IContext): Promise<any> {
    return { success: true }
  }

  async removeKey(args: { identifier: IIdentifier; kid: string; options?: any }, context: IContext): Promise<any> {
    return { success: true }
  }

  async removeService(args: { identifier: IIdentifier; id: string; options?: any }, context: IContext): Promise<any> {
    return { success: true }
  }

  private async importOrCreateKey(args: OydDidHoldKeysArgs, context: IContext): Promise<IKey> {
    const kms = await this.assertedKms(args.kms, this.defaultKms)
    if (args.options.privateKeyHex) {
      return context.agent.keyManagerImport({
        kms,
        type: args.options.keyType,
        kid: args.options.kid,
        privateKeyHex: args.options.privateKeyHex,
        /*meta: {
          algorithms: ['Secp256r1'],
        },*/
      })
    }
    return context.agent.keyManagerCreate({
      type: args.options.keyType,
      kms,
      meta: {
        algorithms: ['Secp256r1'],
      },
    })
  }
}

export function defaultOydCmsmPublicKeyCallback(keyManager: KeyManager): (kid: string, kms?: string, create?: boolean, createKeyType?: TKeyType) => Promise<IKey> {
  return async (kid: string, kms?: string, create?: boolean, createKeyType?: TKeyType): Promise<IKey> => {
    try {
      const existing = await keyManager.keyManagerGet({ kid })
      if (existing) {
        return existing
      }
    } catch (error: any) {}
    if (create) {
      if (!kms) {
        return Promise.reject(Error('No KMS provided, whilst creating a new key!'))
      }
      return await keyManager.keyManagerCreate({ kms, type: createKeyType ?? 'Secp256r1' })
    }
    return Promise.reject(Error('No existing key found, and create is false!'))
  }
}

export function defaultOydCmsmSignCallback(keyManager: KeyManager): (kid: string, data: string) => Promise<string> {
  return async (kid: string, data: string): Promise<string> => {
    return keyManager.keyManagerSign({ keyRef: kid, data, encoding: 'base64' })
  }
}

export class DefaultOydCmsmCallbacks implements CMSMCallbackOpts {
  constructor(private keyManager: KeyManager) {}

  publicKeyCallback: (kid: string, kms?: string, create?: boolean, createKeyType?: TKeyType) => Promise<IKey> = defaultOydCmsmPublicKeyCallback(this.keyManager)

  signCallback: (kid: string, value: string) => Promise<string> = defaultOydCmsmSignCallback(this.keyManager)
}
