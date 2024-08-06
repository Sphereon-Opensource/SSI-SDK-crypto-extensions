import * as x509 from '@peculiar/x509'
import { areCertificatesEqual, createX509Certificate, pemCertChainTox5c } from './x509-utils'


export const validateX5cCertificateChain = async (
  x5c: string[],
  trustedCertificates?: string[],
  verificationTime: Date = new Date(),
): Promise<boolean> => {
  if (x5c.length === 0) {
    return Promise.reject(Error('Certificate chain must not be empty'))
  }

  const parsedCertificates = x5c.map(createX509Certificate)
  const chainBuilder = new x509.X509ChainBuilder({ certificates: parsedCertificates })

  const leafCertificate = parsedCertificates[0]
  const chain = await chainBuilder.build(leafCertificate)

  const isChainValid = chain.slice(0, -1).every(async (cert, index) => {
    const issuerCert = chain[index + 1]
    return cert.verify({
      date: verificationTime,
      publicKey: issuerCert.publicKey,
    })
  })

  if (!isChainValid) {
    return false
  }

  // When trustedCertificates suppliued, check if the chain ends with a trusted certificate
  if (trustedCertificates) {
    const rootCert = chain[chain.length - 1]
    const isTrusted = await Promise.all(trustedCertificates.map(async trustedCert => {
      const parsedTrustedCert = createX509Certificate(trustedCert)
      return areCertificatesEqual(rootCert, parsedTrustedCert)
    }))

    if (!isTrusted.some(result => result)) {
      return false // TODO or do we want to Promise.reject here with an error message?
    }
  }

  return true
}


export const validatePEMCertificateChain = async (
  pemCertChain: string,
  trustedCertificates?: string[],
  verificationDate?: Date,
): Promise<boolean> => {
  const x5c = pemCertChainTox5c(pemCertChain)
  return validateX5cCertificateChain(x5c, trustedCertificates, verificationDate)
}
