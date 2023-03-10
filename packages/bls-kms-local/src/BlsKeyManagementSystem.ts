import Debug from 'debug'

import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core'
import { AbstractPrivateKeyStore, ManagedPrivateKey } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { BlsManagedKeyInfoArgs, KeyType } from './index'

import { RSASigner } from './x509/rsa-signer'
import { hexToPEM, jwkToPEM, pemCertChainTox5c, PEMToHex, PEMToJwk, privateKeyHexFromPEM } from '@sphereon/ssi-sdk-did-utils'
import { generateRSAKeyAsPEM, signAlgorithmToSchemeAndHashAlg } from './x509/rsa-key'
import { Bls12381G2KeyPair } from '@transmute/bls12381-key-pair'
import crypto from '@sphereon/isomorphic-webcrypto'

import * as u8a from 'uint8arrays'

const debug = Debug('veramo:kms:bls:local')

export async function generateBls12381G2KeyPair(): Promise<Bls12381G2KeyPair> {
  // await crypto.ensureSecure()
  const array = new Uint8Array(1)
  crypto.getRandomValues(array)
  const random = new Uint8Array(64)
  const keyPairBls12381G2 = await Bls12381G2KeyPair.generate({
    secureRandom: () => {
      return crypto.getRandomValues(random)
    },
  })
  return keyPairBls12381G2
}

export async function hexToBls12381G2KeyPair({
  privateKeyHex,
  publicKeyHex,
  kid,
}: {
  privateKeyHex: string
  publicKeyHex?: string
  kid: string
}): Promise<Bls12381G2KeyPair> {
  const privateKey = u8a.fromString(privateKeyHex, 'hex')
  const publicKey = u8a.fromString(publicKeyHex ?? kid, 'hex') // BLS uses the publickey as kid for now
  const publicKeyBase58 = u8a.toString(publicKey, 'base58btc')
  // @ts-ignore
  const fingerPrint = await Bls12381G2KeyPair.fingerprintFromPublicKey({ publicKeyBase58, type: 'Bls12381G2Key2020' })
  const keypair = new Bls12381G2KeyPair({
    publicKey,
    privateKey,
    id: kid,
    controller: fingerPrint,
    type: 'Bls12381G2Key2020',
  })
  return keypair
}

export class BlsKeyManagementSystem extends KeyManagementSystem {
  private readonly privateKeyStore: AbstractPrivateKeyStore
  // private readonly publicKeyStore: AbstractKeyStore

  constructor(privateKeyStore: AbstractPrivateKeyStore /*, publicKeyStore: AbstractKeyStore*/) {
    super(privateKeyStore)
    this.privateKeyStore = privateKeyStore
    // this.publicKeyStore = publicKeyStore
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'>): Promise<ManagedKeyInfo> {
    switch (args.type) {
      case KeyType.Bls12381G2.toString():
        if (!args.privateKeyHex || !args.publicKeyHex) {
          throw new Error('invalid_argument: type, publicKeyHex and privateKeyHex are required to import a key')
        }
        if (!args.kid) {
          args.kid = args.publicKeyHex
        }
        if (args.kid !== args.publicKeyHex) {
          throw Error('For now Bls1238G2 keys need to be imported with a kid that is the same as the public key!')
        }
        const managedKey = this.asBlsManagedKeyInfo({
          alias: args.kid,
          privateKeyHex: args.privateKeyHex,
          publicKeyHex: args.publicKeyHex,
          type: args.type,
        })
        await this.privateKeyStore.import({ alias: managedKey.kid, ...args })
        // We use the public keystore here as it will use the private key store. We only need the private key store when we are signing
        // await this.publicKeyStore.import({ alias: managedKey.kid, kms: this., ...args})
        debug('imported key', managedKey.type, managedKey.publicKeyHex)
        return managedKey

      // @ts-ignore
      case 'RSA': {
        if (!args.privateKeyHex) {
          throw new Error('invalid_argument: type and privateKeyHex are required to import a key')
        }
        const managedKey = this.asBlsManagedKeyInfo({ alias: args.kid, ...args })
        await this.privateKeyStore.import({ alias: managedKey.kid, ...args })
        debug('imported key', managedKey.type, managedKey.publicKeyHex)
        return managedKey
      }
      default:
        return await super.importKey(args)
    }
  }

  async createKey({ type }: { type: TKeyType }): Promise<ManagedKeyInfo> {
    let key: ManagedKeyInfo

    switch (type) {
      case KeyType.Bls12381G2: {
        const keyPairBls12381G2 = await generateBls12381G2KeyPair()
        if (!keyPairBls12381G2.privateKey || !keyPairBls12381G2.publicKey) {
          throw Error('No private/public keys create for Bls12381G2 key')
        }
        const publicKeyHex = u8a.toString(keyPairBls12381G2.publicKey, 'hex')
        key = await this.importKey({
          type,
          kid: publicKeyHex, // BLS uses the public key as kid for now
          privateKeyHex: u8a.toString(keyPairBls12381G2.privateKey, 'hex'),
          publicKeyHex,
        })
        break
      }

      // @ts-ignore
      case 'RSA': {
        const pem = await generateRSAKeyAsPEM('RSA-PSS', 'SHA-256', 2048)
        key = await this.importKey({
          type,
          privateKeyHex: privateKeyHexFromPEM(pem),
        })
        break
      }
      default:
        key = await super.createKey({ type })
    }

    debug('Created key', type, key.publicKeyHex)

    return key
  }

  async sign({ keyRef, algorithm, data }: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array }): Promise<string> {
    let managedPrivateKey: ManagedPrivateKey
    try {
      managedPrivateKey = await this.privateKeyStore.get({ alias: keyRef.kid })
    } catch (e) {
      throw new Error(`key_not_found: No key entry found for kid=${keyRef.kid}`)
    }
    // const publicKey = await this.publicKeyStore.get({kid: keyRef.kid})

    if (managedPrivateKey.type === KeyType.Bls12381G2) {
      if (!data || Array.isArray(data)) {
        throw new Error('Data must be defined and cannot be an array')
      }
      const keypair = await hexToBls12381G2KeyPair({ privateKeyHex: managedPrivateKey.privateKeyHex, kid: keyRef.kid })
      return u8a.toString(await keypair.signer().sign({ data }), 'hex')
    } else if (
      // @ts-ignore
      managedPrivateKey.type === 'RSA' &&
      (typeof algorithm === 'undefined' || algorithm === 'RS256' || algorithm === 'RS512' || algorithm === 'PS256' || algorithm === 'PS512')
    ) {
      return await this.signRSA(managedPrivateKey.privateKeyHex, data, algorithm ? algorithm : 'PS256')
    } else {
      return await super.sign({ keyRef, algorithm, data })
    }
    throw Error(`not_supported: Cannot sign using key of type ${managedPrivateKey.type}`)
  }

  private asBlsManagedKeyInfo(args: BlsManagedKeyInfoArgs): ManagedKeyInfo {
    let key: Partial<ManagedKeyInfo>
    switch (args.type) {
      case KeyType.Bls12381G2:
        key = {
          type: args.type,
          kid: args.alias || args.publicKeyHex,
          publicKeyHex: args.publicKeyHex,
          meta: {
            algorithms: ['BLS', 'Bls12381G2', 'Bls12381G2Key2020'],
          },
        }
        break
      // @ts-ignore
      case 'RSA': {
        // @ts-ignore // We need this as the interface on the args, does not allow for any metadata on managed key imports
        const x509 = args.meta?.x509 as X509Opts
        const privateKeyPEM = args.privateKeyHex.includes('---') ? args.privateKeyHex : hexToPEM(args.privateKeyHex, 'private') // In case we have x509 opts, the private key hex really was a PEM already (yuck)
        const publicKeyJwk = PEMToJwk(privateKeyPEM, 'public')
        const publicKeyPEM = jwkToPEM(publicKeyJwk, 'public')
        const publicKeyHex = PEMToHex(publicKeyPEM)

        const meta = {} as any
        if (x509) {
          meta.x509 = {
            cn: x509.cn || args.alias || publicKeyHex,
          }
          let certChain: string = x509.certificateChainPEM || ''
          if (x509.certificatePEM) {
            if (!certChain.includes(x509.certificatePEM)) {
              certChain = `${x509.certificatePEM}\n${certChain}`
            }
          }
          if (certChain.length > 0) {
            meta.x509.certificateChainPEM = certChain
            const x5c = pemCertChainTox5c(certChain)
            if (!x509.certificateChainURL) {
              // Do not put the chain in the JWK when the chain is hosted. We do put it in the x509 metadata
              // @ts-ignore
              publicKeyJwk.x5c = x5c
            }
            meta.x509.x5c = x5c
          }
          if (x509.certificateChainURL) {
            // @ts-ignore
            publicKeyJwk.x5u = x509.certificateChainURL
            meta.x509.x5u = x509.certificateChainURL
          }
        }

        key = {
          type: args.type,
          kid: args.alias || meta?.x509?.cn || publicKeyHex,
          publicKeyHex,
          meta: {
            ...meta,
            // todo: could als be DSA etc
            algorithms: ['RS256', 'RS512', 'PS256', 'PS512'],
            publicKeyJwk,
            publicKeyPEM,
          },
        }
        break
      }

      default:
        throw Error('not_supported: Key type not supported: ' + args.type)
    }
    return key as ManagedKeyInfo
  }

  /**
   * @returns a base64url encoded signature for the `RS256` alg
   */
  private async signRSA(privateKeyHex: string, data: Uint8Array, signingAlgorithm: string): Promise<string> {
    const { hashAlgorithm, scheme } = signAlgorithmToSchemeAndHashAlg(signingAlgorithm)
    const signer = new RSASigner(PEMToJwk(hexToPEM(privateKeyHex, 'private'), 'private'), { hashAlgorithm, scheme })
    const signature = await signer.sign(data)
    return signature as string
  }
}
