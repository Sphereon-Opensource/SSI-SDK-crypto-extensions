import {
  ErrorMessage,
  ExternalIdentifierOIDFEntityIdOpts,
  ExternalIdentifierOIDFEntityIdResult, ExternalJwkInfo,
  PublicKeyHex,
  TrustedAnchor,
} from '../types'
import { IAgentContext } from '@veramo/core'
import { IOIDFClient } from '@sphereon/ssi-sdk.oidf-client'
import { contextHasPlugin } from '@sphereon/ssi-sdk.agent-config'
import { JWK } from '@sphereon/ssi-types'
import { IJwsValidationResult, VerifyJwsArgs } from '../types/IJwtService'

/**
 * Resolves an OIDF Entity ID against multiple trust anchors to establish trusted relationships
 *
 * @param opts Configuration options containing the identifier to resolve and trust anchors to validate against
 * @param context Agent context that must include the OIDF client plugin and JWT verification capabilities
 *
 * @returns Promise resolving to an ExternalIdentifierOIDFEntityIdResult containing:
 *  - trustedAnchors: Record mapping trust anchors to their public key hexes
 *  - errorList: Optional record of errors encountered per trust anchor
 *  - jwks: Array of JWK information from the trust chain
 *  - trustEstablished: Boolean indicating if any trust relationships were established
 *
 * @throws Error if trust anchors are missing or JWT verification plugin is not enabled
 */
export async function resolveExternalOIDFEntityIdIdentifier(
  opts: ExternalIdentifierOIDFEntityIdOpts,
  context: IAgentContext<IOIDFClient>
): Promise<ExternalIdentifierOIDFEntityIdResult> {
  let { trustAnchors, identifier } = opts

  if (!trustAnchors || trustAnchors.length === 0) {
    return Promise.reject(Error('ExternalIdentifierOIDFEntityIdOpts is missing the trustAnchors'))
  }

  if (!contextHasPlugin(context, 'jwtVerifyJwsSignature')) {
    return Promise.reject(Error('For OIDFEntityId resolving the agent needs to have the JwtService plugin enabled'))
  }

  const trustedAnchors: Record<TrustedAnchor, PublicKeyHex> = {}
  const errorList: Record<TrustedAnchor, ErrorMessage> = {}
  const jwkInfos: Array<ExternalJwkInfo> = []

  for (const trustAnchor of trustAnchors) {
    const resolveResult = await context.agent.resolveTrustChain({
      entityIdentifier: identifier,
      trustAnchors: [trustAnchor]
    })

    if (resolveResult.error || !resolveResult.trustChain) {
      errorList[trustAnchor] = resolveResult.errorMessage ?? 'unspecified'
    } else {
      const trustChain: ReadonlyArray<string> = resolveResult.trustChain.asJsReadonlyArrayView()
      let authorityJWK:JWK | undefined = undefined
      for (const [i, jwt] of [...trustChain].reverse().entries()) {
        const isLast = i === trustChain.length - 1

        const verifyArgs:VerifyJwsArgs = {jws: jwt}
        if(authorityJWK && !isLast) {
          verifyArgs.jwk = authorityJWK
        }
        
        // FIXME remove jwtVerifyJwsSignature as the Kotlin client already did this
        const jwtVerifyResult:IJwsValidationResult = await context.agent.jwtVerifyJwsSignature(verifyArgs)
        if(jwtVerifyResult.error || jwtVerifyResult.critical) {
          errorList[trustAnchor] = jwtVerifyResult.message
          break
        }
        if(jwtVerifyResult.jws.signatures.length === 0) {
          errorList[trustAnchor] = 'No signature was present in the trust anchor JWS'
          break
        }
        const signature = jwtVerifyResult.jws.signatures[0]
        if(signature.identifier.jwks.length === 0) {
          errorList[trustAnchor] = 'No JWK was present in the trust anchor signature'
          break
        }
        const jwkInfo:ExternalJwkInfo = signature.identifier.jwks[0]
        if(!authorityJWK) {
          authorityJWK = jwkInfo.jwk
          jwkInfos.push(jwkInfo)
          trustedAnchors[trustAnchor] = signature.publicKeyHex // When we have multiple hits from different trust anchor authorities the caller can infer which signature came from which trust anchor  
        }
      }
    }
  }

  return {
    method: 'entity_id',
    trustedAnchors,
    ...(Object.keys(errorList).length > 0 && { errorList }),
    jwks: jwkInfos,
    trustEstablished: Object.keys(trustedAnchors).length > 0
  }
}
