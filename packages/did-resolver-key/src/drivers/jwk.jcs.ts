import { DIDDocument } from 'did-resolver'
import { decode } from '../JwkJcsBlockCodec'
import { DID_LD_JSON } from '../index'

export const keyToDidDoc = (pubKeyBytes: Uint8Array, fingerprint: string, contentType: string): DIDDocument => {
  const did = `did:key:${fingerprint}`
  const keyId = `${did}#${fingerprint}`
  const publicKeyJwk = decode(pubKeyBytes)
  return {
    ...(contentType === DID_LD_JSON && {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    }),
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    capabilityInvocation: [keyId],
  }
}
export default { keyToDidDoc }
