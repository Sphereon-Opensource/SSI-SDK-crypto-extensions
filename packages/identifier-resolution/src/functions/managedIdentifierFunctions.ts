import { getFirstKeyWithRelation } from '@sphereon/ssi-sdk-ext.did-utils'
import { calculateJwkThumbprint, JWK, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'
import { pemOrDerToX509Certificate } from '@sphereon/ssi-sdk-ext.x509-utils'
import { contextHasDidManager, contextHasKeyManager } from '@sphereon/ssi-sdk.agent-config'
import { IAgentContext, IIdentifier, IKey, IKeyManager } from '@veramo/core'
import { Certificate, CryptoEngine, setEngine } from 'pkijs'
import {
  isManagedIdentifierDidOpts,
  isManagedIdentifierJwkOpts,
  isManagedIdentifierKidOpts,
  isManagedIdentifierX5cOpts,
  ManagedIdentifierOpts,
  ManagedIdentifierResult,
} from '../types'

export async function getManagedIdentifier(
  opts: ManagedIdentifierOpts & {
    crypto?: Crypto
  },
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierResult> {
  let { method } = opts
  let identifier: IIdentifier | undefined = undefined
  let keys: IKey[] | undefined = undefined
  let key: IKey | undefined = undefined
  let certificate: Certificate | undefined = undefined
  let jwk: JWK | undefined = undefined
  let jwkThumbprint: string | undefined = undefined
  let x5c: string[] | undefined
  let controllerKeyId: string | undefined = undefined
  let did: string | undefined = undefined
  const cryptoImpl = opts.crypto ?? crypto
  if (isManagedIdentifierKidOpts(opts)) {
    method = 'kid'
    if (!contextHasKeyManager(context)) {
      return Promise.reject(Error(`Cannot get Key/JWK identifier if KeyManager plugin is not enabled!`))
    }
    key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? opts.identifier })
  } else if (isManagedIdentifierDidOpts(opts)) {
    method = 'did'
    if (!contextHasDidManager(context)) {
      return Promise.reject(Error(`Cannot get DID identifier if DID Manager plugin is not enabled!`))
    }

    if (typeof opts.identifier === 'string') {
      identifier = await context.agent.didManagerGet({ did: opts.identifier.split('#')[0] })
    } else {
      identifier = opts.identifier
    }
    if (identifier) {
      did = identifier.did
      keys = identifier?.keys // fixme: We really want to return the vmRelationship keys here actually
      key = await getFirstKeyWithRelation(
        {
          ...opts,
          identifier,
          vmRelationship: opts.vmRelationship ?? 'verificationMethod',
        },
        context
      )
      controllerKeyId = identifier.controllerKeyId
    }
  } else if (isManagedIdentifierJwkOpts(opts)) {
    method = 'jwk'
    if (!contextHasKeyManager(context)) {
      return Promise.reject(Error(`Cannot get Key/JWK identifier if KeyManager plugin is not enabled!`))
    }
    key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? calculateJwkThumbprint({ jwk: opts.identifier }) })
  } else if (isManagedIdentifierX5cOpts(opts)) {
    method = 'x5c'
    x5c = opts.identifier
    if (x5c.length === 0) {
      return Promise.reject(`Cannot resolve x5c when an empty x5c is passed in`)
    } else if (!contextHasKeyManager(context)) {
      return Promise.reject(Error(`Cannot get X5c identifier if KeyManager plugin is not enabled!`))
    }
    certificate = pemOrDerToX509Certificate(x5c[0])
    const cryptoEngine = new CryptoEngine({ name: 'identifier_resolver_managed', crypto: cryptoImpl })
    setEngine(cryptoEngine.name, cryptoEngine)
    const pk = await certificate.getPublicKey(undefined, cryptoEngine)
    jwk = (await cryptoEngine.subtle.exportKey('jwk', pk)) as JWK
    jwkThumbprint = calculateJwkThumbprint({ jwk })
    key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? jwkThumbprint })
  } else {
    return Promise.reject(Error(`Could not determine identifier method. Please provide explicitly`))
  }
  if (!key || (isManagedIdentifierDidOpts(opts) && !identifier)) {
    console.log(`Cannot find identifier`, opts.identifier)
    return Promise.reject(`Cannot find identifier ${opts.identifier}`)
  }
  jwk = jwk ?? toJwk(key.publicKeyHex, key.type, { key })
  const thumbprint = jwkThumbprint ?? key.meta?.jwkThumbprint ?? calculateJwkThumbprint({ jwk })
  return {
    method,
    jwk,
    jwkThumbprint: thumbprint,
    ...(identifier && { identifier }),
    ...(did && { did }),
    ...(controllerKeyId && { controllerKeyId }),
    ...(keys && { keys }),
    ...(certificate && { certificate: certificate.toJSON() }),
    key,
    kmsKeyRef: key.kid,
  } as ManagedIdentifierResult
}
