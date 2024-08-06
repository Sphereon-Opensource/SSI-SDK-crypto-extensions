import * as x509 from '@peculiar/x509'
import { areCertificatesEqual, pemOrDerToX509Certificate } from './x509-utils'

export type X509ValidationResult = {
  error: boolean
  critical: boolean
  message: string
  verificationTime: Date
}

/**
 *
 * @param pemOrDerChain The order must be that the Certs signing another cert must come one after another. So first the signing cert, then any cert signing that cert and so on
 * @param trustedPEMs
 * @param verificationTime
 * @param opts
 */
export const validateX509CertificateChain = async ({
  chain: pemOrDerChain,
  trustedCerts: trustedPEMs,
  verificationTime = new Date(),
  opts = { exactChainRequired: true },
}: {
  chain: (Uint8Array | string)[]
  trustedCerts?: string[]
  verificationTime?: Date
  opts?: { exactChainRequired?: boolean }
}): Promise<X509ValidationResult> => {
  if (pemOrDerChain.length === 0) {
    return { error: true, critical: true, message: 'Certificate chain in DER or PEM format must not be empty', verificationTime }
  }
  const { exactChainRequired } = opts

  const certs = pemOrDerChain.map(pemOrDerToX509Certificate)
  const chainBuilder = new x509.X509ChainBuilder({ certificates: certs })

  const leafCertificate = certs[0]
  const calculateChain = await chainBuilder.build(leafCertificate)
  if (pemOrDerChain.length > 0 && calculateChain.length < pemOrDerChain.length) {
    return {
      error: true,
      critical: true,
      message: `Calculated chain length ${calculateChain.length} is smaller than provided chain length ${pemOrDerChain.length}.`,
      verificationTime,
    }
  } else if (exactChainRequired && calculateChain.length !== pemOrDerChain.length) {
    return {
      error: true,
      critical: true,
      message: `Calculated chain length ${calculateChain.length} is different from provided chain length ${pemOrDerChain.length} and exact chain matching was enabled.`,
      verificationTime,
    }
  }

  for (const cert of calculateChain.slice(0, -1)) {
    const index = calculateChain.slice(0, -1).indexOf(cert)
    const issuerCert = calculateChain[index + 1]
    if (exactChainRequired && !certs.includes(issuerCert)) {
      return {
        error: true,
        critical: true,
        message: `Issuer certificate ${issuerCert.subject} from cert ${cert.subject} was not provided as input chain, and exact chain matching was enabled`,
        verificationTime,
      }
    }
    const valid = await cert.verify({
      date: verificationTime,
      publicKey: issuerCert.publicKey,
    })
    if (!valid) {
      return {
        error: true,
        critical: true,
        message: `Certificate nr ${index + 1}, ${cert.subject} was not valid`,
        verificationTime,
      }
    }
  }

  // When trustedCertificates supplied, check if the chain ends with a trusted certificate
  if (trustedPEMs) {
    if (trustedPEMs.length === 0) {
      return {
        error: true,
        critical: true,
        message: `An array of trusted certificates was provided, but it was empty. If you do not want validation against trusted certificates provide null/undefined`,
        verificationTime,
      }
    }

    const trustedCerts = trustedPEMs.map(pemOrDerToX509Certificate)
    // todo: We probably should also be okay if a trusted intermediary cert is provided. Right now we only look at the root
    const caCert = calculateChain[calculateChain.length - 1]

    for (const trustedCert of trustedCerts) {
      const result = await areCertificatesEqual(caCert, trustedCert)
      if (result) {
        return {
          error: false,
          critical: false,
          message: `Certificate chain was valid`,
          verificationTime,
        }
      }
    }
    return {
      error: true,
      critical: true,
      message: `Root certificate nr ${certs.length}, ${calculateChain[calculateChain.length - 1].subject} was not found in trusted certificates`,
      verificationTime,
    }
  }

  return {
    error: false,
    critical: false,
    message: `Certificate chain was valid`,
    verificationTime,
  }
}
