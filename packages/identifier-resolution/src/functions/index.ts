import { IIdentifier } from '@veramo/core'
import { ManagedIdentifierDidOpts, ManagedIdentifierOpts } from '../types'

export * from './managedIdentifierFunctions'
export * from './externalIdentifierFunctions'

/**
 * Converts legacy id opts key refs to the new ManagedIdentifierOpts
 * @param opts
 */
export function legacyKeyRefsToIdentifierOpts(opts: {
  idOpts?: ManagedIdentifierOpts
  iss?: string
  keyRef?: string
  didOpts?: any
}): ManagedIdentifierOpts {
  if (!opts.idOpts) {
    console.warn(
      `Legacy idOpts being used. Support will be dropped in the future. Consider switching to the idOpts, to have support for DIDs, JWKS, x5c etc. See https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/tree/feature/multi_identifier_support/packages/identifier-resolution`
    )
    // legacy way
    let kmsKeyRef =
      opts.keyRef ??
      opts.didOpts?.idOpts?.kmsKeyRef ??
      (typeof opts.didOpts?.idOpts.identifier === 'object' ? (opts.didOpts?.idOpts.identifier as IIdentifier).keys[0].kid : undefined)
    if (!kmsKeyRef) {
      throw Error('Key ref is needed for access token signer')
    }
    return {
      kmsKeyRef: opts.keyRef ?? kmsKeyRef,
      identifier: kmsKeyRef,
      issuer: opts.iss,
    } satisfies ManagedIdentifierDidOpts
  } else {
    const idOpts = opts.idOpts
    if (opts.keyRef && !idOpts.kmsKeyRef) {
      // legacy way
      console.warn(
        `Legacy keyRef being used. Support will be dropped in the future. Consider switching to the idOpts, to have support for DIDs, JWKS, x5c etc. See https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/tree/feature/multi_identifier_support/packages/identifier-resolution`
      )
      idOpts.kmsKeyRef = opts.keyRef
    }
    if (opts.iss && !idOpts.issuer) {
      // legacy way
      console.warn(
        `Legacy iss being used. Support will be dropped in the future. Consider switching to the idOpts, to have support for DIDs, JWKS, x5c etc. See https://github.com/Sphereon-Opensource/SSI-SDK-crypto-extensions/tree/feature/multi_identifier_support/packages/identifier-resolution`
      )
      idOpts.issuer = opts.iss
    }

    return idOpts
  }
}
