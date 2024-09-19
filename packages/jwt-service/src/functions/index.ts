import { jwkTtoPublicKeyHex } from '@sphereon/ssi-sdk-ext.did-utils'
import {
  ensureManagedIdentifierResult,
  ExternalIdentifierDidOpts,
  ExternalIdentifierX5cOpts,
  IIdentifierResolution,
  isManagedIdentifierDidResult,
  isManagedIdentifierX5cResult,
  ManagedIdentifierMethod,
  ManagedIdentifierResult,
  resolveExternalJwkIdentifier,
} from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { keyTypeFromCryptographicSuite, verifySignatureWithSubtle } from '@sphereon/ssi-sdk-ext.key-utils'
import { contextHasPlugin } from '@sphereon/ssi-sdk.agent-config'
import { JWK } from '@sphereon/ssi-types'
import { IAgentContext } from '@veramo/core'
import { bytesToBase64url, decodeJoseBlob, encodeJoseBlob } from '@veramo/utils'
import { base64ToBytes } from '@veramo/utils'
import * as u8a from 'uint8arrays'
import {
  CreateJwsCompactArgs,
  CreateJwsFlattenedArgs,
  CreateJwsJsonArgs,
  IJwsValidationResult,
  IRequiredContext,
  isJwsCompact,
  isJwsJsonFlattened,
  isJwsJsonGeneral,
  Jws,
  JwsCompact,
  JwsIdentifierMode,
  JwsJsonFlattened,
  JwsJsonGeneral,
  JwsJsonGeneralWithIdentifiers,
  JwsJsonSignature, JwsJsonSignatureWithIdentifier,
  JwtHeader,
  JwtPayload,
  PreparedJwsObject,
  VerifyJwsArgs,
} from '../types/IJwtService'

const payloadToBytes = (payload: string | JwtPayload | Uint8Array): Uint8Array => {
  const isBytes = payload instanceof Uint8Array
  const isString = typeof payload === 'string'
  return isBytes ? payload : isString ? u8a.fromString(payload, 'base64url') : u8a.fromString(JSON.stringify(payload), 'utf-8')
}

export const prepareJwsObject = async (args: CreateJwsJsonArgs, context: IRequiredContext): Promise<PreparedJwsObject> => {
  const { existingSignatures, protectedHeader, unprotectedHeader, issuer, payload, mode = 'auto', clientId, clientIdScheme } = args

  const { noIdentifierInHeader = false } = issuer
  const identifier = await ensureManagedIdentifierResult(issuer, context)
  await checkAndUpdateJwtHeader({ mode, identifier, noIdentifierInHeader, header: protectedHeader }, context)
  const isBytes = payload instanceof Uint8Array
  const isString = typeof payload === 'string'
  if (!isBytes && !isString) {
    if (issuer.noIssPayloadUpdate !== true && !payload.iss && identifier.issuer) {
      payload.iss = identifier.issuer
    }
    if (clientIdScheme && !payload.client_id_scheme) {
      payload.client_id_scheme = clientIdScheme
    }
    if (clientId && !payload.client_id) {
      payload.client_id = clientId
    }
  }
  const payloadBytes = payloadToBytes(payload)
  const base64urlHeader = encodeJoseBlob(protectedHeader)
  const base64urlPayload = bytesToBase64url(payloadBytes)

  return {
    jws: {
      unprotectedHeader,
      protectedHeader,
      payload: payloadBytes,
      existingSignatures,
    },
    b64: {
      protectedHeader: base64urlHeader,
      payload: base64urlPayload,
    },
    identifier,
  }
}

export const createJwsCompact = async (args: CreateJwsCompactArgs, context: IRequiredContext): Promise<JwsCompact> => {
  const { protected: protectedHeader, payload, signature } = await createJwsJsonFlattened(args, context)
  return `${protectedHeader}.${payload}.${signature}`
}

export const createJwsJsonFlattened = async (args: CreateJwsFlattenedArgs, context: IRequiredContext): Promise<JwsJsonFlattened> => {
  const jws = await createJwsJsonGeneral(args, context)
  if (jws.signatures.length !== 1) {
    return Promise.reject(Error(`JWS flattened signature can only contain 1 signature. Found ${jws.signatures.length}`))
  }
  return {
    ...jws.signatures[0],
    payload: jws.payload,
  } satisfies JwsJsonFlattened
}

export const createJwsJsonGeneral = async (args: CreateJwsJsonArgs, context: IRequiredContext): Promise<JwsJsonGeneral> => {
  const { payload, protectedHeader, unprotectedHeader, existingSignatures, mode, issuer } = args
  const { b64, identifier } = await prepareJwsObject(
    {
      protectedHeader,
      unprotectedHeader,
      payload,
      existingSignatures,
      issuer,
      mode,
    },
    context
  )
  // const algorithm = await signatureAlgorithmFromKey({ key: identifier.key })
  const signature = await context.agent.keyManagerSign({
    keyRef: identifier.kmsKeyRef,
    data: `${b64.protectedHeader}.${b64.payload}`,
    encoding: undefined,
  })
  const jsonSignature = {
    protected: b64.protectedHeader,
    header: unprotectedHeader,
    signature,
  } satisfies JwsJsonSignature
  return {
    payload: b64.payload,
    signatures: [...(existingSignatures ?? []), jsonSignature],
  } satisfies JwsJsonGeneral
}

/**
 * Updates the JWT header to include x5c, kid, jwk objects using the supplied issuer identifier that will be used to sign. If not present will automatically make the header objects available
 * @param mode The type of header to check or include
 * @param identifier The identifier of the signer. This identifier will be used later to sign
 * @param header The JWT header
 * @param noIdentifierInHeader
 * @param context
 */

export const checkAndUpdateJwtHeader = async (
  {
    mode = 'auto',
    identifier,
    header,
    noIdentifierInHeader = false,
  }: {
    mode?: JwsIdentifierMode
    identifier: ManagedIdentifierResult
    noIdentifierInHeader?: boolean
    header: JwtHeader
  },
  context: IRequiredContext
) => {
  if (isIdentifierMode(mode, identifier.method, 'did')) {
    // kid is VM of the DID
    // @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
    await checkAndUpdateDidHeader({ header, identifier, noIdentifierInHeader }, context)
  } else if (isIdentifierMode(mode, identifier.method, 'x5c')) {
    // Include the x5c in the header. No kid
    // @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    await checkAndUpdateX5cHeader({ header, identifier, noIdentifierInHeader }, context)
  } else if (isIdentifierMode(mode, identifier.method, 'kid', false)) {
    await checkAndUpdateKidHeader({ header, identifier, noIdentifierInHeader }, context)
  } else if (isIdentifierMode(mode, identifier.method, 'jwk', false)) {
    // Include the JWK in the header as well as its kid if present
    // @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3
    // @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
    await checkAndUpdateJwkHeader({ header, identifier, noIdentifierInHeader }, context)
  } else {
    // Better safe than sorry. We could let it pass, but we want to force implementers to make a conscious choice
    return Promise.reject(`Invalid combination of JWS creation mode ${mode} and identifier method ${identifier.method} chosen`)
  }
}

const checkAndUpdateX5cHeader = async (
  {
    header,
    identifier,
    noIdentifierInHeader = false,
  }: {
    header: JwtHeader
    identifier: ManagedIdentifierResult
    noIdentifierInHeader?: boolean
  },
  context: IRequiredContext
) => {
  const { x5c } = header
  if (x5c) {
    // let's resolve the provided x5c to be sure
    const x5cIdentifier = await context.agent.identifierManagedGetByX5c({ identifier: x5c })
    if (x5cIdentifier.kmsKeyRef !== identifier.kmsKeyRef) {
      return Promise.reject(Error(`An x5c header was present, but its issuer public key did not match the provided signing public key!`))
    }
  } else if (!noIdentifierInHeader) {
    if (!isManagedIdentifierX5cResult(identifier)) {
      return Promise.reject(Error('No x5c header in the JWT, but mode was x5c and also no x5x identifier was provided!'))
    } else if (header.jwk || header.kid) {
      return Promise.reject(Error('x5c mode was choosen, but jwk or kid headers were provided. These cannot be used together!'))
    }
    header.x5c = identifier.x5c
  }
}

const checkAndUpdateDidHeader = async (
  {
    header,
    identifier,
    noIdentifierInHeader = false,
  }: {
    header: JwtHeader
    identifier: ManagedIdentifierResult
    noIdentifierInHeader?: boolean
  },
  context: IRequiredContext
) => {
  const { kid } = header
  if (kid) {
    // let's resolve the provided x5c to be sure
    const vmIdentifier = await context.agent.identifierManagedGetByDid({ identifier: kid })
    if (vmIdentifier.kmsKeyRef !== identifier.kmsKeyRef) {
      return Promise.reject(Error(`A kid header was present, but its value did not match the provided signing kid!`))
    }
  } else if (!noIdentifierInHeader) {
    if (!isManagedIdentifierDidResult(identifier)) {
      return Promise.reject(Error('No kid header in the JWT, but mode was did and also no DID identifier was provided!'))
    } else if (header.jwk || header.x5c) {
      return Promise.reject(Error('did mode was chosen, but jwk or x5c headers were provided. These cannot be used together!'))
    }
    header.kid = identifier.kid
  }
}

const checkAndUpdateJwkHeader = async (
  {
    header,
    identifier,
    noIdentifierInHeader = false,
  }: {
    header: JwtHeader
    identifier: ManagedIdentifierResult
    noIdentifierInHeader?: boolean
  },
  context: IRequiredContext
) => {
  const { jwk } = header
  if (jwk) {
    // let's resolve the provided x5c to be sure
    const jwkIdentifier = await context.agent.identifierManagedGetByJwk({ identifier: jwk })
    if (jwkIdentifier.kmsKeyRef !== identifier.kmsKeyRef) {
      return Promise.reject(Error(`A jwk header was present, but its value did not match the provided signing jwk or kid!`))
    }
  } else if (!noIdentifierInHeader) {
    // We basically accept everything for this mode, as we can always create JWKs from any key
    if (header.x5c) {
      return Promise.reject(Error('jwk mode was chosen, but x5c headers were provided. These cannot be used together!'))
    }
    header.jwk = identifier.jwk
  }
}

const checkAndUpdateKidHeader = async (
  {
    header,
    identifier,
    noIdentifierInHeader = false,
  }: {
    header: JwtHeader
    identifier: ManagedIdentifierResult
    noIdentifierInHeader?: boolean
  },
  context: IRequiredContext
) => {
  const { kid } = header
  if (kid) {
    // let's resolve the provided x5c to be sure
    const kidIdentifier = await context.agent.identifierManagedGetByKid({ identifier: kid })
    if (kidIdentifier.kmsKeyRef !== identifier.kmsKeyRef) {
      return Promise.reject(Error(`A kid header was present, but its value did not match the provided signing kid!`))
    }
  } else if (!noIdentifierInHeader) {
    // We basically accept everything for this mode, as we can always create JWKs from any key
    if (header.x5c) {
      return Promise.reject(Error('kid mode was chosen, but x5c headers were provided. These cannot be used together!'))
    }
    header.kid = identifier.kid
  }
}

const isIdentifierMode = (mode: JwsIdentifierMode, identifierMethod: ManagedIdentifierMethod, checkMode: JwsIdentifierMode, loose = true) => {
  if (loose && (checkMode === 'jwk' || checkMode === 'kid')) {
    // we always have the kid and jwk at hand no matter the identifier method, so we are okay with that
    // todo: check the impact on the above expressions, as this will now always return true for the both of them
    return true
  }
  if (mode === checkMode) {
    if (checkMode !== 'auto' && mode !== identifierMethod) {
      throw Error(`Provided mode ${mode} conflicts with identifier method ${identifierMethod}`)
    }
    return true
  }
  // we always have the kid and jwk at hand no matter the identifier method, so we are okay with that
  return mode === 'auto' && identifierMethod === checkMode
}

export const verifyJws = async (args: VerifyJwsArgs, context: IAgentContext<IIdentifierResolution>): Promise<IJwsValidationResult> => {
  const jws = await toJwsJsonGeneralWithIdentifiers(args, context)

  let errorMessages: string[] = []
  let index = 0
  await Promise.all(
    jws.signatures.map(async (sigWithId) => {
      // If we have a specific KMS agent plugin that can do the verification prefer that over the generic verification
      index++
      let valid: boolean
      const data = u8a.fromString(`${sigWithId.protected}.${jws.payload}`, 'utf-8')
      const jwkInfo = sigWithId.identifier.jwks[0]
      if (sigWithId.header?.alg === 'RSA' && contextHasPlugin(context, 'keyManagerVerify')) {
        const publicKeyHex = jwkTtoPublicKeyHex(jwkInfo.jwk)
        valid = await context.agent.keyManagerVerify({
          signature: sigWithId.signature,
          data,
          publicKeyHex,
          type: keyTypeFromCryptographicSuite({ suite: jwkInfo.jwk.crv ?? 'ES256' }),
          // no kms arg, as the current key manager needs a bit more work
        })
      } else {
        const signature = base64ToBytes(sigWithId.signature)
        valid = await verifySignatureWithSubtle({ data, signature, key: jwkInfo.jwk })
      }
      if (!valid) {
        errorMessages.push(`Signature ${index} was not valid`)
      }

      return {
        sigWithId,
        valid,
      }
    })
  )
  const error = errorMessages.length !== 0
  return {
    name: 'jws',
    jws,
    error,
    critical: error,
    message: error ? errorMessages.join(', ') : 'Signature validated',
    verificationTime: new Date(),
  } satisfies IJwsValidationResult
}
export const toJwsJsonGeneral = async ({ jws }: { jws: Jws }, context: IAgentContext<any>): Promise<JwsJsonGeneral> => {
  let payload: string
  let signatures: JwsJsonSignature[] = []

  if (isJwsCompact(jws)) {
    const split = jws.split('.')
    payload = split[1]
    signatures[0] = {
      protected: split[0],
      signature: split[2],
    } satisfies JwsJsonSignature
  } else if (isJwsJsonGeneral(jws)) {
    payload = jws.payload
    signatures = jws.signatures
  } else if (isJwsJsonFlattened(jws)) {
    const { payload: _payload, ...signature } = jws
    payload = _payload
    signatures = [signature]
  } else {
    return Promise.reject(Error(`Invalid JWS supplied`))
  }
  return {
    payload,
    signatures,
  }
}

async function resolveExternalIdentifierFromJwsHeader(
  protectedHeader: JwtHeader,
  context: IAgentContext<IIdentifierResolution>,
  args: {
    jws: Jws
    opts?: { x5c?: Omit<ExternalIdentifierX5cOpts, 'identifier'>; did?: Omit<ExternalIdentifierDidOpts, 'identifier'> }
  }
) {
  if (protectedHeader.x5c) {
    const x5c = protectedHeader.x5c
    return await context.agent.identifierExternalResolveByX5c({
      ...args.opts?.x5c,
      identifier: x5c,
      verify: true,
    })
  } else if (protectedHeader.jwk) {
    const jwk = protectedHeader.jwk
    const x5c = jwk.x5c // todo resolve x5u
    return await context.agent.identifierExternalResolveByJwk({
      identifier: protectedHeader.jwk,
      ...(x5c && {
        x5c: {
          ...args?.opts?.x5c,
          identifier: x5c,
        },
      }),
    })
  } else if (protectedHeader.kid && protectedHeader.kid.startsWith('did:')) {
    return await context.agent.identifierExternalResolveByDid({ ...args?.opts?.did, identifier: protectedHeader.kid })
  } else if (protectedHeader.alg === 'none') {
    return undefined
  } else {
    return Promise.reject(Error(`We can only process DIDs, X.509 certificate chains and JWKs for signature validation at present`))
  }
}

export const toJwsJsonGeneralWithIdentifiers = async (
  args: {
    jws: Jws
    jwk?: JWK
    opts?: { x5c?: Omit<ExternalIdentifierX5cOpts, 'identifier'>; did?: Omit<ExternalIdentifierDidOpts, 'identifier'> }
  },
  context: IAgentContext<IIdentifierResolution>
): Promise<JwsJsonGeneralWithIdentifiers> => {
  const jws = await toJwsJsonGeneral(args, context)
  const signatures = (await Promise.all(
    jws.signatures.map(async (signature) => {
      const protectedHeader: JwtHeader = decodeJoseBlob(signature.protected)
      const identifier = args.jwk
        ? await resolveExternalJwkIdentifier({ identifier: args.jwk }, context)
        : await resolveExternalIdentifierFromJwsHeader(protectedHeader, context, args)
      if (identifier !== undefined) {
        return { ...signature, identifier }
      }
      return undefined
    })
  )).filter(signature => signature !== undefined ) as JwsJsonSignatureWithIdentifier[]
  
  return { payload: jws.payload, signatures }
}
