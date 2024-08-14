import { getFirstKeyWithRelation } from '@sphereon/ssi-sdk-ext.did-utils'
import { calculateJwkThumbprint, JWK, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'
import { pemOrDerToX509Certificate } from '@sphereon/ssi-sdk-ext.x509-utils'
import { contextHasDidManager, contextHasKeyManager } from '@sphereon/ssi-sdk.agent-config'
import { IAgentContext, IIdentifier, IKey, IKeyManager } from '@veramo/core'
import { CryptoEngine, setEngine } from 'pkijs'
import {
  isManagedIdentifierDidOpts,
  isManagedIdentifierDidResult,
  isManagedIdentifierJwkOpts,
  isManagedIdentifierKeyOpts,
  isManagedIdentifierKidOpts,
  isManagedIdentifierX5cOpts,
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
} from '../types'

export async function getManagedKidIdentifier(
  opts: ManagedIdentifierKidOpts,
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierKidResult> {
  const method = 'kid'
  if (!contextHasKeyManager(context)) {
    return Promise.reject(Error(`Cannot get Key/JWK identifier if KeyManager plugin is not enabled!`))
  }
  const key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? opts.identifier })
  const jwk = toJwk(key.publicKeyHex, key.type, { key })
  const jwkThumbprint = (key.meta?.jwkThumbprint as string) ?? calculateJwkThumbprint({ jwk })
  const kid = opts.kid ?? (key.meta?.verificationMethod?.id as string) ?? jwkThumbprint
  const issuer = opts.issuer ?? kid // The different identifiers should set the value. Defaults to the kid
  return {
    method,
    key,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
    kmsKeyRef: key.kid,
  } satisfies ManagedIdentifierKidResult
}

/**
 * This function is just a convenience function to get a common result. The user already apparently had a key, so could have called the kid version as well
 * @param opts
 * @param _context
 */
export async function getManagedKeyIdentifier(opts: ManagedIdentifierKeyOpts, _context?: IAgentContext<any>): Promise<ManagedIdentifierKeyResult> {
  const method = 'key'
  const key: IKey = opts.identifier
  if (opts.kmsKeyRef && opts.kmsKeyRef !== key.kid) {
    return Promise.reject(Error(`Cannot get a managed key object by providing a key and a kmsKeyRef that are different.}`))
  }
  const jwk = toJwk(key.publicKeyHex, key.type, { key })
  const jwkThumbprint = (key.meta?.jwkThumbprint as string) ?? calculateJwkThumbprint({ jwk })
  const kid = opts.kid ?? (key.meta?.verificationMethod?.id as string) ?? jwkThumbprint
  const issuer = opts.issuer ?? kid // The different identifiers should set the value. Defaults to the kid
  return {
    method,
    key,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
    kmsKeyRef: key.kid,
  } satisfies ManagedIdentifierKeyResult
}

export async function getManagedDidIdentifier(opts: ManagedIdentifierDidOpts, context: IAgentContext<any>): Promise<ManagedIdentifierDidResult> {
  const method = 'did'
  if (!contextHasDidManager(context)) {
    return Promise.reject(Error(`Cannot get DID identifier if DID Manager plugin is not enabled!`))
  }

  let identifier: IIdentifier
  if (typeof opts.identifier === 'string') {
    identifier = await context.agent.didManagerGet({ did: opts.identifier.split('#')[0] })
  } else {
    identifier = opts.identifier
  }

  const did = identifier.did
  const keys = identifier?.keys // fixme: We really want to return the vmRelationship keys here actually
  const extendedKey = await getFirstKeyWithRelation(
    {
      ...opts,
      identifier,
      vmRelationship: opts.vmRelationship ?? 'verificationMethod',
    },
    context
  )
  const key = extendedKey
  const controllerKeyId = identifier.controllerKeyId
  const jwk = toJwk(key.publicKeyHex, key.type, { key })
  const jwkThumbprint = key.meta?.jwkThumbprint ?? calculateJwkThumbprint({ jwk })
  const kid = opts.kid ?? extendedKey.meta?.verificationMethod?.id
  const issuer = opts.issuer ?? did
  return {
    method,
    key,
    did,
    kmsKeyRef: key.kid,
    jwk,
    jwkThumbprint,
    controllerKeyId,
    kid,
    keys,
    issuer,
    identifier,
  }
}

export async function getManagedJwkIdentifier(
  opts: ManagedIdentifierJwkOpts,
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierJwkResult> {
  const method = 'jwk'
  const { kid, issuer } = opts
  if (!contextHasKeyManager(context)) {
    return Promise.reject(Error(`Cannot get Key/JWK identifier if KeyManager plugin is not enabled!`))
  }
  const key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? calculateJwkThumbprint({ jwk: opts.identifier }) })
  const jwk = opts.identifier ?? toJwk(key.publicKeyHex, key.type, { key })
  const jwkThumbprint = (key.meta?.jwkThumbprint as string) ?? calculateJwkThumbprint({ jwk })
  // we explicitly do not set the kid and issuer, meaning it can remain null. Normally you do not provide a kid and issuer with Jwks.
  return {
    method,
    key,
    kmsKeyRef: key.kid,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
  } satisfies ManagedIdentifierJwkResult
}

export async function getManagedX5cIdentifier(
  opts: ManagedIdentifierX5cOpts & {
    crypto?: Crypto
  },
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierX5cResult> {
  const { kid, issuer } = opts
  const method = 'x5c'
  const x5c = opts.identifier
  if (x5c.length === 0) {
    return Promise.reject(`Cannot resolve x5c when an empty x5c is passed in`)
  } else if (!contextHasKeyManager(context)) {
    return Promise.reject(Error(`Cannot get X5c identifier if KeyManager plugin is not enabled!`))
  }
  const cryptoImpl = opts.crypto ?? crypto
  const certificate = pemOrDerToX509Certificate(x5c[0])
  const cryptoEngine = new CryptoEngine({ name: 'identifier_resolver_managed', crypto: cryptoImpl })
  setEngine(cryptoEngine.name, cryptoEngine)
  const pk = await certificate.getPublicKey(undefined, cryptoEngine)
  const jwk = (await cryptoEngine.subtle.exportKey('jwk', pk)) as JWK
  const jwkThumbprint = calculateJwkThumbprint({ jwk })
  const key = await context.agent.keyManagerGet({ kid: opts.kmsKeyRef ?? jwkThumbprint })
  // we explicitly do not set the kid and issuer, meaning it can remain null. Normally you do not provide a kid and issuer with x5c.

  return {
    method,
    x5c,
    certificate,
    jwk,
    jwkThumbprint,
    key,
    kmsKeyRef: key.kid,
    kid,
    issuer,
  } satisfies ManagedIdentifierX5cResult
}

export async function getManagedIdentifier(
  opts: ManagedIdentifierOpts & {
    crypto?: Crypto
  },
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierResult> {
  let resolutionResult: ManagedIdentifierResult
  if (isManagedIdentifierKidOpts(opts)) {
    resolutionResult = await getManagedKidIdentifier(opts, context)
  } else if (isManagedIdentifierDidOpts(opts)) {
    resolutionResult = await getManagedDidIdentifier(opts, context)
  } else if (isManagedIdentifierJwkOpts(opts)) {
    resolutionResult = await getManagedJwkIdentifier(opts, context)
  } else if (isManagedIdentifierX5cOpts(opts)) {
    resolutionResult = await getManagedX5cIdentifier(opts, context)
  } else if (isManagedIdentifierKeyOpts(opts)) {
    resolutionResult = await getManagedKeyIdentifier(opts, context)
  } else {
    return Promise.reject(Error(`Could not determine identifier method. Please provide explicitly`))
  }
  const { key } = resolutionResult
  if (!key || (isManagedIdentifierDidOpts(opts) && isManagedIdentifierDidResult(resolutionResult) && !resolutionResult.identifier)) {
    console.log(`Cannot find identifier`, opts.identifier)
    return Promise.reject(`Cannot find identifier ${opts.identifier}`)
  }
  return resolutionResult
}
