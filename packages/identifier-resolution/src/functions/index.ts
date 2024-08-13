import { didDocumentToJwks, getAgentResolver, getFirstKeyWithRelation } from '@sphereon/ssi-sdk-ext.did-utils'
import { calculateJwkThumbprint, JWK, toJwk } from '@sphereon/ssi-sdk-ext.key-utils'
import { getSubjectDN, pemOrDerToX509Certificate, validateX509CertificateChain, X509ValidationResult } from '@sphereon/ssi-sdk-ext.x509-utils'
import { contextHasDidManager, contextHasKeyManager, contextHasPlugin } from '@sphereon/ssi-sdk.agent-config'
import { IParsedDID, parseDid } from '@sphereon/ssi-types'
import { IAgentContext, IDIDManager, IIdentifier, IKey, IKeyManager, IResolver } from '@veramo/core'
import { Certificate, CryptoEngine, setEngine } from 'pkijs'
import {
  ExternalIdentifierDidOpts,
  ExternalIdentifierDidResult,
  ExternalIdentifierMethod,
  ExternalIdentifierOpts,
  ExternalIdentifierResult,
  ExternalIdentifierX5cOpts,
  ExternalIdentifierX5cResult,
  ExternalJwkInfo,
  isExternalIdentifierDidOpts,
  isExternalIdentifierJwksUrlOpts,
  isExternalIdentifierKidOpts,
  isExternalIdentifierOidcDiscoveryOpts,
  isExternalIdentifierX5cOpts,
  isManagedIdentifierDidOpts,
  isManagedIdentifierJwkOpts,
  isManagedIdentifierKidOpts,
  isManagedIdentifierX5cOpts,
  ManagedIdentifierOpts,
  ManagedIdentifierResult,
} from '../types/IIdentifierResolution'

export async function resolveExternalIdentifier(
  opts: ExternalIdentifierOpts & {
    crypto?: Crypto
  },
  context: IAgentContext<any>
): Promise<ExternalIdentifierResult> {
  let method: ExternalIdentifierMethod | undefined
  if (isExternalIdentifierDidOpts(opts)) {
    return resolveExternalDidIdentifier(opts, context)
  } else if (isExternalIdentifierX5cOpts(opts)) {
    return resolveExternalX5cIdentifier(opts, context)
  } else if (isExternalIdentifierKidOpts(opts)) {
    method = 'kid'
  } else if (isExternalIdentifierJwksUrlOpts(opts)) {
    method = 'jwks-url'
  } else if (isExternalIdentifierOidcDiscoveryOpts(opts)) {
    method = 'oidc-discovery'
  }
  throw Error(`External resolution method ${method} is not yet implemented`)
}

export async function resolveExternalX5cIdentifier(
  opts: ExternalIdentifierX5cOpts & {
    crypto?: Crypto
  },
  context: IAgentContext<IResolver & IDIDManager>
): Promise<ExternalIdentifierX5cResult> {
  if (!isExternalIdentifierX5cOpts(opts)) {
    return Promise.reject('External x5c Identifier args need to be provided')
  }
  const verify = opts.verify ?? true
  const x5c = opts.identifier
  if (x5c.length === 0) {
    return Promise.reject('Empty certification chain is now allowed')
  }
  const certificates = x5c.map(pemOrDerToX509Certificate)

  let verificationResult: X509ValidationResult | undefined
  let issuerJWK: JWK | undefined
  let jwks: ExternalJwkInfo[] = []

  if (verify) {
    // We use the agent plugin if it is available as that is more powerful, but revert to the function otherwise
    if (contextHasPlugin(context, 'verifyCertificateChain')) {
      verificationResult = (await context.agent.verifyCertificateChain({
        chain: opts.identifier,
        trustAnchors: opts.trustAnchors ?? [],
        verificationTime: opts.verificationTime,
      })) as X509ValidationResult // We need to cast, as we know this is the value and we do not want to rely on the x509 plugin perse
    } else {
      verificationResult = await validateX509CertificateChain({
        chain: opts.identifier,
        trustAnchors: opts.trustAnchors ?? [],
        verificationTime: opts.verificationTime,
      })
    }
    if (verificationResult.certificateChain) {
      jwks = verificationResult.certificateChain.map((cert) => {
        return {
          jwk: cert.publicKeyJWK,
          kid: cert.subject.dn.DN,
          jwkThumbprint: calculateJwkThumbprint(cert.publicKeyJWK),
        } satisfies ExternalJwkInfo
      })
    }
  }
  if (!jwks) {
    const cryptoEngine = new CryptoEngine({
      name: 'identifier_resolver_external',
      crypto: opts.crypto ?? global.crypto,
    })
    setEngine(cryptoEngine.name, cryptoEngine)
    jwks = await Promise.all(
      certificates.map(async (cert) => {
        const pk = await cert.getPublicKey(undefined, cryptoEngine)
        const jwk = (await cryptoEngine.exportKey('jwk', pk)) as JWK
        return {
          jwk,
          kid: getSubjectDN(cert).DN,
          jwkThumbprint: calculateJwkThumbprint({ jwk }),
        } satisfies ExternalJwkInfo
      })
    )
  }
  if (jwks.length === 0) {
    return Promise.reject('Empty certification chain is now allowed')
  }
  if (!issuerJWK) {
    issuerJWK = jwks[0].jwk
  }

  return {
    method: 'x5c',
    verificationResult,
    issuerJWK,
    jwks,
    certificates,
    x5c,
  }
}

export async function resolveExternalDidIdentifier(
  opts: ExternalIdentifierDidOpts,
  context: IAgentContext<IResolver & IDIDManager>
): Promise<ExternalIdentifierDidResult> {
  if (!isExternalIdentifierDidOpts(opts)) {
    return Promise.reject('External DID Identifier args need to be provided')
  } else if (!contextHasPlugin<IResolver & IDIDManager>(context, 'resolveDid')) {
    return Promise.reject(Error(`Cannot get external DID identifier if DID resolver plugin is not enabled!`))
  }
  const { uniresolverResolution = false, localResolution = true, resolverResolution = true } = opts
  const did = opts.identifier
  let parsed: IParsedDID
  try {
    parsed = parseDid(did)
  } catch (error: unknown) {
    // Error from did resolution spec
    return Promise.reject(error)
  }
  const didParsed = parsed
  const didResolutionResult = await getAgentResolver(context, {
    uniresolverResolution,
    localResolution,
    resolverResolution,
  }).resolve(did)
  const didDocument = didResolutionResult.didDocument ?? undefined
  const didJwks = didDocument ? didDocumentToJwks(didDocument) : undefined
  const jwks = didJwks
    ? Array.from(new Set(Object.values(didJwks).flatMap((jwks) => jwks))).map((jwk) => {
        return { jwk, jwkThumbprint: calculateJwkThumbprint({ jwk }), kid: jwk.kid }
      })
    : []

  if (didResolutionResult?.didDocument) {
    // @ts-ignore // Mandatory on the original object, but we already provide it directly
    delete didResolutionResult['didDocument']
  }
  return {
    method: 'did',
    did,
    jwks,
    didJwks,
    didDocument,
    didResolutionResult,
    didParsed,
  }
}

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
