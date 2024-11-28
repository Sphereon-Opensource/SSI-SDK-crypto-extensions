import { IAgentPlugin } from '@veramo/core'
import {
  createJwsCompact,
  CreateJwsCompactArgs,
  CreateJwsFlattenedArgs,
  CreateJwsJsonArgs,
  createJwsJsonFlattened,
  createJwsJsonGeneral,
  DecryptJweCompactJwtArgs,
  EncryptJweCompactJwtArgs,
  IJwsValidationResult,
  IJwtService,
  IRequiredContext,
  jweAlg,
  jweEnc,
  JwsJsonFlattened,
  JwsJsonGeneral,
  JwtCompactResult,
  JwtLogger,
  PreparedJwsObject,
  prepareJwsObject,
  schema,
  verifyJws,
  VerifyJwsArgs,
} from '..'
import { CompactJwtEncrypter } from '../functions/JWE'

import * as u8a from 'uint8arrays'

/**
 * @public
 */
export class JwtService implements IAgentPlugin {
  readonly schema = schema.IJwtService
  readonly methods: IJwtService = {
    jwtPrepareJws: this.jwtPrepareJws.bind(this),
    jwtCreateJwsJsonGeneralSignature: this.jwtCreateJwsJsonGeneralSignature.bind(this),
    jwtCreateJwsJsonFlattenedSignature: this.jwtCreateJwsJsonFlattenedSignature.bind(this),
    jwtCreateJwsCompactSignature: this.jwtCreateJwsCompactSignature.bind(this),
    jwtVerifyJwsSignature: this.jwtVerifyJwsSignature.bind(this),
    jwtEncryptJweCompactJwt: this.jwtEncryptJweCompactJwt.bind(this),
    jwtDecryptJweCompactJwt: this.jwtDecryptJweCompactJwt.bind(this),
  }

  private async jwtPrepareJws(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<PreparedJwsObject> {
    return await prepareJwsObject(args, context)
  }

  private async jwtCreateJwsJsonGeneralSignature(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<JwsJsonGeneral> {
    return await createJwsJsonGeneral(args, context)
  }

  private async jwtCreateJwsJsonFlattenedSignature(args: CreateJwsFlattenedArgs, context: IRequiredContext): Promise<JwsJsonFlattened> {
    return await createJwsJsonFlattened(args, context)
  }

  private async jwtCreateJwsCompactSignature(args: CreateJwsCompactArgs, context: IRequiredContext): Promise<JwtCompactResult> {
    // We wrap it in a json object for remote REST calls
    return { jwt: await createJwsCompact(args, context) }
  }

  private async jwtVerifyJwsSignature(args: VerifyJwsArgs, context: IRequiredContext): Promise<IJwsValidationResult> {
    return await verifyJws(args, context)
  }

  private async jwtEncryptJweCompactJwt(args: EncryptJweCompactJwtArgs, context: IRequiredContext): Promise<JwtCompactResult> {
    const { payload, protectedHeader = { alg: args.alg, enc: args.enc }, recipientKey, issuer, expirationTime, audience } = args

    console.log(JSON.stringify(args, null, 2))

    const alg = jweAlg(args.alg) ?? jweAlg(protectedHeader.alg) ?? 'ECDH-ES'
    const enc = jweEnc(args.enc) ?? jweEnc(protectedHeader.enc) ?? 'A256GCM'
    const encJwks =
      recipientKey.jwks.length === 1
        ? [recipientKey.jwks[0]]
        : recipientKey.jwks.filter((jwk) => (jwk.kid && (jwk.kid === jwk.jwk.kid || jwk.kid === jwk.jwkThumbprint)) || jwk.jwk.use === 'enc')
    if (encJwks.length === 0) {
      return Promise.reject(Error(`No public JWK found that can be used to encrypt against`))
    }
    const jwkInfo = encJwks[0]
    if (encJwks.length > 0) {
      JwtLogger.warning(`More than one JWK with 'enc' usage found. Selected the first one as no 'kid' was provided`, encJwks)
    }
    if (jwkInfo.jwk.kty?.startsWith('EC') !== true || !alg.startsWith('ECDH')) {
      return Promise.reject(Error(`Currently only ECDH-ES is supported for encryption. JWK alg ${jwkInfo.jwk.kty}, header alg ${alg}`)) // TODO: Probably we support way more already
    }
    const apuVal = protectedHeader.apu ?? args.apu
    const apu = apuVal ? u8a.fromString(apuVal, 'base64url') : undefined
    const apvVal = protectedHeader.apv ?? args.apv
    const apv = apvVal ? u8a.fromString(apvVal, 'base64url') : undefined

    const pubKey = await crypto.subtle.importKey(
      'jwk',
      jwkInfo.jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    )
    const encrypter = new CompactJwtEncrypter({
      enc,
      alg,
      keyManagementParams: { apu, apv },
      key: pubKey,
      issuer,
      expirationTime,
      audience,
    })

    const jwe = await encrypter.encryptCompactJWT(payload, {})
    return { jwt: jwe }
  }

  private async jwtDecryptJweCompactJwt(args: DecryptJweCompactJwtArgs, context: IRequiredContext): Promise<JwtCompactResult> {
    return { jwt: 'FIXME' }
  }
}
