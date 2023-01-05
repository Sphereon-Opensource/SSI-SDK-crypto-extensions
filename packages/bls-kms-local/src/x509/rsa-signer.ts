import JSEncrypt from '@sphereon/jsencrypt'
import * as u8a from 'uint8arrays'
import { jwkToPEM } from './x509-utils'
import { DigestMethodName, digestMethodParams } from './digest-methods'

export class RSASigner {
  private readonly jsEncrypt: JSEncrypt
  private readonly digestMethodName

  /**
   *
   * @param key Either in PEM or JWK format (no raw hex keys here!)
   * @param digestMethodName
   */
  constructor(key: string | JsonWebKey, digestMethodName?: DigestMethodName) {
    this.jsEncrypt = new JSEncrypt()
    if (typeof key === 'string') {
      this.jsEncrypt.setKey(key)
    } else {
      this.jsEncrypt.setKey(jwkToPEM(key, key.d ? 'private' : 'public'))
    }
    this.digestMethodName = digestMethodName ?? 'sha256'
  }

  public async sign(data: string | Uint8Array): Promise<string> {
    const input = typeof data === 'string' ? data : u8a.toString(data)
    const dmParams = digestMethodParams(this.digestMethodName)
    const result = this.jsEncrypt.sign(input, dmParams.digestMethod, dmParams.digestName)
    if (!result) {
      throw Error('Could not sign input data')
    }
    return result
  }

  public async verify(data: string | Uint8Array, signature: string | Uint8Array): Promise<boolean> {
    const input = typeof data === 'string' ? data : u8a.toString(data)
    const dmParams = digestMethodParams(this.digestMethodName)
    return this.jsEncrypt.verify(input, typeof signature === 'string' ? signature : u8a.toString(signature), dmParams.digestMethod)
  }
}
