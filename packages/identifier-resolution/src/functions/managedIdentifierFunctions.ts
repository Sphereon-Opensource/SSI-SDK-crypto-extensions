import { getFirstKeyWithRelation } from '@sphereon/ssi-sdk-ext.did-utils'
import { calculateJwkThumbprint, JWK, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'
import { pemOrDerToX509Certificate } from '@sphereon/ssi-sdk-ext.x509-utils'
import { contextHasDidManager, contextHasKeyManager } from '@sphereon/ssi-sdk.agent-config'
import { IAgentContext, IIdentifier, IKey, IKeyManager } from '@veramo/core'
import { CryptoEngine, setEngine } from 'pkijs'
import {
  IIdentifierResolution,
  isManagedIdentifierDidOpts,
  isManagedIdentifierDidResult,
  isManagedIdentifierJwkOpts,
  isManagedIdentifierJwkResult,
  isManagedIdentifierKeyOpts,
  isManagedIdentifierKeyResult,
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
  ManagedIdentifierOptsOrResult,
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
    identifier: opts.identifier,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
    kmsKeyRef: key.kid,
    opts,
  } satisfies ManagedIdentifierKidResult
}

function isManagedIdentifierResult(identifier: ManagedIdentifierOptsOrResult & { crypto?: Crypto }): identifier is ManagedIdentifierResult {
  return 'key' in identifier && 'kmsKeyRef' in identifier && 'method' in identifier && 'opts' in identifier
}

/**
 * Allows to get a managed identifier result in case identifier options are passed in, but returns the identifier directly in case results are passed in. This means resolution can have happened before, or happens in this method
 * @param identifier
 * @param context
 */
export async function ensureManagedIdentifierResult(
  identifier: ManagedIdentifierOptsOrResult & {
    crypto?: Crypto
  },
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierResult> {
  const { lazyDisabled = false } = identifier
  return !lazyDisabled && isManagedIdentifierResult(identifier) ? identifier : await getManagedIdentifier(identifier, context)
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
    identifier: key,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
    kmsKeyRef: key.kid,
    opts,
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
  let kid = opts.kid ?? extendedKey.meta?.verificationMethod?.id
  if (!kid.startsWith(did)) {
    // Make sure we create a fully qualified kid
    const hash = kid.startsWith('#') ? '' : '#'
    kid = `${did}${hash}${kid}`
  }
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
    opts,
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
    identifier: jwk,
    jwk,
    jwkThumbprint,
    kid,
    issuer,
    opts,
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
    identifier: x5c,
    certificate,
    jwk,
    jwkThumbprint,
    key,
    kmsKeyRef: key.kid,
    kid,
    issuer,
    opts,
  } satisfies ManagedIdentifierX5cResult
}

export async function getManagedIdentifier(
  opts: ManagedIdentifierOptsOrResult & {
    crypto?: Crypto
  },
  context: IAgentContext<IKeyManager>
): Promise<ManagedIdentifierResult> {
  let resolutionResult: ManagedIdentifierResult
  if (isManagedIdentifierResult(opts)) {
    opts
  }
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

export async function managedIdentifierToKeyResult(
  identifier: ManagedIdentifierOptsOrResult,
  context: IAgentContext<IIdentifierResolution & IKeyManager>
): Promise<ManagedIdentifierKeyResult> {
  const resolved = await ensureManagedIdentifierResult(identifier, context)
  if (isManagedIdentifierKeyResult(resolved)) {
    return resolved
  }
  return {
    ...resolved,
    method: 'key',
    identifier: resolved.key,
  } satisfies ManagedIdentifierKeyResult
}

export async function managedIdentifierToJwk(
  identifier: ManagedIdentifierOptsOrResult,
  context: IAgentContext<IIdentifierResolution & IKeyManager>
): Promise<ManagedIdentifierJwkResult> {
  const resolved = await ensureManagedIdentifierResult(identifier, context)
  if (isManagedIdentifierJwkResult(resolved)) {
    return resolved
  }
  return {
    ...resolved,
    method: 'jwk',
    identifier: resolved.jwk,
  } satisfies ManagedIdentifierJwkResult
}
