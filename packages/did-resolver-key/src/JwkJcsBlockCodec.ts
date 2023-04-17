import { TextDecoder, TextEncoder } from 'web-encoding'
import isPlainObject from 'lodash.isplainobject'
import type { ByteView } from 'multiformats/codecs/interface'
import type { JsonWebKey } from 'did-resolver'

export declare const name = 'jwk_jcs-pub'
export declare const code = 0xeb51

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
/**
 * Checks if the value is a non-empty string.
 *
 * @param value - The value to check.
 * @param description - Description of the value to check.
 */
function check(value: unknown, description: string) {
  if (typeof value !== 'string' || !value) {
    throw new Error(`${description} missing or invalid`)
  }
}
/**
 * Checks if the value is a valid JSON object.
 *
 * @param value - The value to check.
 */
function validatePlainObject(value: unknown) {
  if (!isPlainObject(value)) {
    throw new Error('JWK must be an object')
  }
}
/**
 * Checks if the JWK is valid. It must contain all the required members.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6
 * @see https://www.rfc-editor.org/rfc/rfc8037#section-2
 *
 * @param jwk - The JWK to check.
 */
function validateJwk(jwk: any) {
  validatePlainObject(jwk)
  // Check JWK required members based on the key type
  switch (jwk.kty) {
    /**
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1
     */
    case 'EC':
      check(jwk.crv, '"crv" (Curve) Parameter')
      check(jwk.x, '"x" (X Coordinate) Parameter')
      check(jwk.y, '"y" (Y Coordinate) Parameter')
      break
    /**
     * @see https://www.rfc-editor.org/rfc/rfc8037#section-2
     */
    case 'OKP':
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter')
      check(jwk.x, '"x" (Public Key) Parameter')
      break
    /**
     * @see https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1
     */
    case 'RSA':
      check(jwk.e, '"e" (Exponent) Parameter')
      check(jwk.n, '"n" (Modulus) Parameter')
      break
    default:
      throw new Error('"kty" (Key Type) Parameter missing or unsupported')
  }
}
/**
 * Extracts the required members of the JWK and canonicalises it.
 * This method is not part of the BlockCodec interface.
 *
 * @param jwk - The JWK to canonicalise.
 * @returns The JWK with only the required members, ordered lexicographically.
 */
function canonicaliseJwk(jwk: any) {
  let components
  // "default" case is not needed
  // eslint-disable-next-line default-case
  switch (jwk.kty) {
    case 'EC':
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      break
    case 'OKP':
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      break
    case 'RSA':
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n }
      break
  }
  return components
}
/**
 * Encodes a JWK into a Uint8Array. Only the required JWK members are encoded.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6
 * @see https://www.rfc-editor.org/rfc/rfc8037#section-2
 * @see https://github.com/panva/jose/blob/3b8aa47b92d07a711bf5c3125276cc9a011794a4/src/jwk/thumbprint.ts#L37
 *
 * @param jwk - JSON Web Key.
 * @returns Uint8Array-encoded JWK.
 */
export function encode(jwk: unknown): Uint8Array {
  validateJwk(jwk)
  // Keep only the JWK required members
  const components = canonicaliseJwk(jwk)
  return textEncoder.encode(JSON.stringify(components))
}

/**
 * Decodes an array of bytes into a JWK. Throws an error if the JWK is not valid.
 *
 * @param bytes - The array of bytes to decode.
 * @returns The corresponding JSON Web Key.
 */
export function decode(bytes: ByteView<JsonWebKey>): JsonWebKey {
  const jwk = JSON.parse(textDecoder.decode(bytes))
  validateJwk(jwk)
  if (JSON.stringify(jwk) !== JSON.stringify(canonicaliseJwk(jwk))) {
    throw new Error('The JWK embedded in the DID is not correctly formatted')
  }
  return jwk
}
