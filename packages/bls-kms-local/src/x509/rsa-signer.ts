import { JWK, PEMToJwk } from '@sphereon/ssi-sdk-did-utils'
import * as u8a from 'uint8arrays'
import { HashAlgorithm } from './digest-methods'
import crypto from 'isomorphic-webcrypto'
import { importRSAKey, RSAEncryptionSchemes, RSASignatureSchemes } from './rsa-key'

export class RSASigner {
  private readonly hashAlgorithm: HashAlgorithm
  private readonly jwk: JWK

  private key: CryptoKey | undefined
  private readonly scheme: RSAEncryptionSchemes | RSASignatureSchemes

  /**
   *
   * @param key Either in PEM or JWK format (no raw hex keys here!)
   * @param hashAlgorithm
   */
  constructor(key: string | JWK, opts?: { hashAlgorithm?: HashAlgorithm; scheme?: RSAEncryptionSchemes | RSASignatureSchemes }) {
    if (typeof key === 'string') {
      this.jwk = PEMToJwk(key)
    } else {
      this.jwk = key
    }

    this.hashAlgorithm = opts?.hashAlgorithm ?? 'sha-256'
    this.scheme = opts?.scheme ?? 'RSA-PSS'
  }

  private getImportParams(): RsaHashedImportParams {
    return { name: this.scheme, hash: this.hashAlgorithm }
  }

  private async getKey(): Promise<CryptoKey> {
    if (!this.key) {
      this.key = await importRSAKey(this.jwk, this.scheme, this.hashAlgorithm)
    }
    return this.key
  }

  private bufferToString(buf: ArrayBuffer) {
    const uint8Array = new Uint8Array(buf)
    return u8a.toString(uint8Array, 'base64url')
  }

  public async sign(data: string | Uint8Array): Promise<string> {
    const input = typeof data !== 'string' ? data : u8a.fromString(data)
    const key = await this.getKey()
    const signature = this.bufferToString(await crypto.subtle.sign(this.getImportParams(), key, input))
    if (!signature) {
      throw Error('Could not sign input data')
    }
    // console.log(`Signature: ${signature}`)

    return signature
  }

  public async verify(data: string | Uint8Array, signature: string | Uint8Array): Promise<boolean> {
    const input = typeof data !== 'string' ? data : u8a.fromString(data)

    const verificationResult = await crypto.subtle.verify(
      this.getImportParams(),
      await this.getKey(),
      typeof signature === 'string' ? u8a.fromString(signature, 'base64url') : signature,
      input
    )

    // console.log(`Verification result: ${verificationResult}`)

    return verificationResult
  }
}
