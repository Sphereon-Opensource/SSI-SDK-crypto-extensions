import * as u8a from 'uint8arrays'
import crypto from '@sphereon/isomorphic-webcrypto'
import { importRSAKey, RSAEncryptionSchemes, RSASignatureSchemes } from './rsa-key'
import { HashAlgorithm, JWK, PEMToJwk } from '@sphereon/ssi-sdk-ext.key-utils'

export class RSASigner {
  private readonly hashAlgorithm: HashAlgorithm
  private readonly jwk: JWK

  private key: CryptoKey | undefined
  private readonly scheme: RSAEncryptionSchemes | RSASignatureSchemes

  /**
   *
   * @param key Either in PEM or JWK format (no raw hex keys here!)
   * @param opts The algorithm and signature/encryption schemes
   */
  constructor(key: string | JWK, opts?: { hashAlgorithm?: HashAlgorithm; scheme?: RSAEncryptionSchemes | RSASignatureSchemes }) {
    if (typeof key === 'string') {
      this.jwk = PEMToJwk(key)
    } else {
      this.jwk = key
    }

    this.hashAlgorithm = opts?.hashAlgorithm ?? 'SHA-256'
    this.scheme = opts?.scheme ?? 'RSA-PSS'
  }

  private getImportParams(): AlgorithmIdentifier {
    // console.log({ name: this.scheme /*, hash: this.hashAlgorithm*/ })
    return { name: this.scheme /*, hash: this.hashAlgorithm*/ }
  }

  private async getKey(): Promise<CryptoKey> {
    if (!this.key) {
      this.key = await importRSAKey(this.jwk, this.scheme, this.hashAlgorithm)
    }
    return this.key
  }

  private bufferToString(buf: ArrayBuffer) {
    const uint8Array = new Uint8Array(buf)
    return u8a.toString(uint8Array, 'base64url') // Needs to be base64url for JsonWebSignature2020. Don't change!
  }

  public async sign(data: string | Uint8Array): Promise<string> {
    const input = typeof data === 'string' ? u8a.fromString(data, 'utf-8') : data
    const key = await this.getKey()
    const signature = this.bufferToString(await crypto.subtle.sign(this.getImportParams(), key, input))
    if (!signature) {
      throw Error('Could not sign input data')
    }

    //  base64url signature
    return signature
  }

  public async verify(data: string | Uint8Array, signature: string | Uint8Array): Promise<boolean> {
    const sig = typeof signature === 'string' ? signature : u8a.toString(signature, 'base64url')
    const jws = sig.includes('.') ? sig.split('.')[2] : sig

    const input = typeof data == 'string' ? u8a.fromString(data, 'utf-8') : data
    const verificationResult = await crypto.subtle.verify(this.getImportParams(), await this.getKey(), u8a.fromString(jws, 'base64url'), input)
    return verificationResult
  }
}
