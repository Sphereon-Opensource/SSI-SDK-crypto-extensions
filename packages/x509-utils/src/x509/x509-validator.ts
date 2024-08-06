import { AttributeTypeAndValue, Certificate, CertificateChainValidationEngine, CryptoEngine, getCrypto, setEngine } from 'pkijs'
import { pemOrDerToX509Certificate } from './x509-utils'

export type DNInfo = {
  DN: string
  attributes: Record<string, string>
}

export type CertInfo = {
  certificate?: Certificate
  notBefore: Date
  notAfter: Date
  publicKeyJWK?: any
  issuer: {
    dn: DNInfo
  }
  subject: {
    dn: DNInfo
  }
}

export type X509ValidationResult = {
  error: boolean
  critical: boolean
  message: string
  verificationTime: Date
  certificateChain?: Array<CertInfo>
}

const defaultCryptoEngine = () => {
  if (typeof self !== 'undefined') {
    if ('crypto' in self) {
      let engineName = 'webcrypto'
      if ('webkitSubtle' in self.crypto) {
        engineName = 'safari'
      }
      setEngine(engineName, new CryptoEngine({ name: engineName, crypto: crypto }))
    }
  } else if (typeof crypto !== 'undefined' && 'webcrypto' in crypto) {
    const name = 'NodeJS ^15'
    const nodeCrypto = crypto.webcrypto
    // @ts-ignore
    setEngine(name, new CryptoEngine({ name, crypto: nodeCrypto }))
  } else if (typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined') {
    const name = 'crypto'
    setEngine(name, new CryptoEngine({ name, crypto: crypto }))
  }
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
  trustAnchors,
  verificationTime = new Date(),
  opts = { trustRootWhenNoAnchors: false },
}: {
  chain: (Uint8Array | string)[]
  trustAnchors?: string[]
  verificationTime?: Date
  opts?: { trustRootWhenNoAnchors: boolean }
}): Promise<X509ValidationResult> => {
  const { trustRootWhenNoAnchors = false } = opts
  const trustedPEMs = trustRootWhenNoAnchors && !trustAnchors ? [pemOrDerChain[pemOrDerChain.length - 1]] : trustAnchors

  if (pemOrDerChain.length === 0) {
    return {
      error: true,
      critical: true,
      message: 'Certificate chain in DER or PEM format must not be empty',
      verificationTime,
    }
  }

  const certs = pemOrDerChain.map(pemOrDerToX509Certificate)
  const trustedCerts = trustedPEMs ? trustedPEMs.map(pemOrDerToX509Certificate) : undefined
  defaultCryptoEngine()

  const validationEngine = new CertificateChainValidationEngine({
    certs /*crls: [crl1],   ocsps: [ocsp1], */,
    checkDate: verificationTime,
    trustedCerts,
  })

  const verification = await validationEngine.verify()
  if (!verification.result || !verification.certificatePath) {
    return {
      error: true,
      critical: true,
      message: verification.resultMessage !== '' ? verification.resultMessage : `Certificate chain validation failed.`,
      verificationTime,
    }
  }
  const subtle = getCrypto(true).subtle
  const certPath = verification.certificatePath
  const certInfos: Array<CertInfo> = await Promise.all(
    certPath.map(async (certificate) => {
      const pk = await certificate.getPublicKey()
      return {
        issuer: { dn: getIssuerDN(certificate) },
        subject: { dn: getSubjectDN(certificate) },
        publicKeyJWK: await subtle.exportKey('jwk', pk),
        notBefore: certificate.notBefore.value,
        notAfter: certificate.notAfter.value,
        // certificate
      } satisfies CertInfo
    })
  )
  return {
    error: false,
    critical: false,
    message: `Certificate chain was valid`,
    verificationTime,
    certificateChain: certInfos,
  }
}

const rdnmap: Record<string, string> = {
  '2.5.4.6': 'C',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.3': 'CN',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.12': 'T',
  '2.5.4.42': 'GN',
  '2.5.4.43': 'I',
  '2.5.4.4': 'SN',
  '1.2.840.113549.1.9.1': 'E-mail',
}

export const getIssuerDN = (cert: Certificate): DNInfo => {
  return {
    DN: getDNString(cert.issuer.typesAndValues),
    attributes: getDNObject(cert.issuer.typesAndValues),
  }
}

export const getSubjectDN = (cert: Certificate): DNInfo => {
  return {
    DN: getDNString(cert.subject.typesAndValues),
    attributes: getDNObject(cert.subject.typesAndValues),
  }
}

const getDNObject = (typesAndValues: AttributeTypeAndValue[]): Record<string, string> => {
  const DN: Record<string, string> = {}
  for (const typeAndValue of typesAndValues) {
    const type = rdnmap[typeAndValue.type] ?? typeAndValue.type
    DN[type] = typeAndValue.value.getValue()
  }
  return DN
}
const getDNString = (typesAndValues: AttributeTypeAndValue[]): string => {
  return Object.entries(getDNObject(typesAndValues))
    .map(([key, value]) => `${key}=${value}`)
    .join(',')
}
