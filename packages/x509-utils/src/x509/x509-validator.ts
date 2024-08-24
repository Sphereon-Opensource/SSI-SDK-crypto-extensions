import x509 from 'js-x509-utils'
import {
  AltName,
  AttributeTypeAndValue,
  Certificate,
  CertificateChainValidationEngine,
  CryptoEngine,
  getCrypto,
  id_SubjectAltName,
  setEngine,
} from 'pkijs'
import * as u8a from 'uint8arrays'
import { derToPEM, pemOrDerToX509Certificate } from './x509-utils'

export type DNInfo = {
  DN: string
  attributes: Record<string, string>
}

export type CertificateInfo = {
  certificate?: any // We need to fix the schema generator for this to be Certificate(Json) from pkijs
  notBefore: Date
  notAfter: Date
  publicKeyJWK?: any
  issuer: {
    dn: DNInfo
  }
  subject: {
    dn: DNInfo
    subjectAlternativeNames: SubjectAlternativeName[]
  }
}

export type X509ValidationResult = {
  error: boolean
  critical: boolean
  message: string
  verificationTime: Date
  certificateChain?: Array<CertificateInfo>
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

export const getCertificateInfo = async (
  certificate: Certificate,
  opts?: {
    sanTypeFilter: SubjectAlternativeGeneralName | SubjectAlternativeGeneralName[]
  }
): Promise<CertificateInfo> => {
  const publicKeyJWK = await getCertificateSubjectPublicKeyJWK(certificate)
  return {
    issuer: { dn: getIssuerDN(certificate) },
    subject: {
      dn: getSubjectDN(certificate),
      subjectAlternativeNames: getSubjectAlternativeNames(certificate, { typeFilter: opts?.sanTypeFilter }),
    },
    publicKeyJWK: publicKeyJWK,
    notBefore: certificate.notBefore.value,
    notAfter: certificate.notAfter.value,
    // certificate
  } satisfies CertificateInfo
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
  opts = {
    trustRootWhenNoAnchors: false,
    allowSingleNoCAChainElement: true,
    blindlyTrustedAnchors: [],
  },
}: {
  chain: (Uint8Array | string)[]
  trustAnchors?: string[]
  verificationTime?: Date
  opts?: {
    // Trust the supplied root from the chain, when no anchors are being passed in.
    trustRootWhenNoAnchors?: boolean
    // Do not perform a chain validation check if the chain only has a single value. This means only the certificate itself will be validated. No chain checks for CA certs will be performed. Only used when the cert has no issuer
    allowSingleNoCAChainElement?: boolean
    // WARNING: Do not use in production
    // Similar to regular trust anchors, but no validation is performed whatsover. Do not use in production settings! Can be handy with self generated certificates as we perform many validations, making it hard to test with self-signed certs. Only applied in case a chain with 1 element is passed in to really make sure people do not abuse this option
    blindlyTrustedAnchors?: string[]
  }
}): Promise<X509ValidationResult> => {
  const { trustRootWhenNoAnchors = false, allowSingleNoCAChainElement = true, blindlyTrustedAnchors = [] } = opts
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

  if (pemOrDerChain.length === 1) {
    const singleCert = typeof pemOrDerChain[0] === 'string' ? pemOrDerChain[0] : u8a.toString(pemOrDerChain[0], 'base64pad')
    const cert = pemOrDerToX509Certificate(singleCert)
    if (blindlyTrustedAnchors.includes(singleCert)) {
      console.log(`Certificate chain validation success as single cert if blindly trusted. WARNING: ONLY USE FOR TESTING PURPOSES.`)
      return {
        error: false,
        critical: true,
        message: `Certificate chain validation success as single cert if blindly trusted. WARNING: ONLY USE FOR TESTING PURPOSES.`,
        verificationTime,
        certificateChain: [await getCertificateInfo(cert)],
      }
    }
    if (allowSingleNoCAChainElement) {
      const subjectDN = getSubjectDN(cert).DN
      if (!getIssuerDN(cert).DN || getIssuerDN(cert).DN === subjectDN) {
        const passed = await cert.verify()
        return {
          error: !passed,
          critical: true,
          message: `Certificate chain validation for ${subjectDN}: ${passed ? 'successful' : 'failed'}.`,
          verificationTime,
          certificateChain: [await getCertificateInfo(cert)],
        }
      }
    }
  }

  const validationEngine = new CertificateChainValidationEngine({
    certs /*crls: [crl1],   ocsps: [ocsp1], */,
    checkDate: verificationTime,
    trustedCerts,
  })

  try {
    const verification = await validationEngine.verify()
    if (!verification.result || !verification.certificatePath) {
      return {
        error: true,
        critical: true,
        message: verification.resultMessage !== '' ? verification.resultMessage : `Certificate chain validation failed.`,
        verificationTime,
      }
    }
    const certPath = verification.certificatePath
    const certInfos: Array<CertificateInfo> = await Promise.all(
      certPath.map(async (certificate) => {
        return getCertificateInfo(certificate)
      })
    )
    return {
      error: false,
      critical: false,
      message: `Certificate chain was valid`,
      verificationTime,
      certificateChain: certInfos,
    }
  } catch (error: any) {
    return {
      error: true,
      critical: true,
      message: `Certificate chain was invalid, ${error.message ?? '<unknown error>'}`,
      verificationTime,
    }
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

export const getCertificateSubjectPublicKeyJWK = async (pemOrDerCert: string | Uint8Array | Certificate): Promise<JsonWebKey> => {
  const pemOrDerStr =
    typeof pemOrDerCert === 'string'
      ? pemOrDerCert
      : pemOrDerCert instanceof Uint8Array
      ? u8a.toString(pemOrDerCert, 'base64pad')
      : pemOrDerCert.toString('base64')
  const pem = derToPEM(pemOrDerStr)
  const certificate = pemOrDerToX509Certificate(pem)
  try {
    const subtle = getCrypto(true).subtle
    const pk = await certificate.getPublicKey()
    return await subtle.exportKey('jwk', pk)
  } catch (error: any) {
    console.log(`Error in primary get JWK from cert:`, error?.message)
  }
  return await x509.toJwk(pem, 'pem')
}

/**
 *  otherName                       [0]     OtherName,
 *         rfc822Name                      [1]     IA5String,
 *         dNSName                         [2]     IA5String,
 *         x400Address                     [3]     ORAddress,
 *         directoryName                   [4]     Name,
 *         ediPartyName                    [5]     EDIPartyName,
 *         uniformResourceIdentifier       [6]     IA5String,
 *         iPAddress                       [7]     OCTET STRING,
 *         registeredID                    [8]     OBJECT IDENTIFIER }
 */
export enum SubjectAlternativeGeneralName {
  rfc822Name = 1, // email
  dnsName = 2,
  uniformResourceIdentifier = 6,
  ipAddress = 7,
}

export interface SubjectAlternativeName {
  value: string
  type: SubjectAlternativeGeneralName
}

export const getSubjectAlternativeNames = (
  certificate: Certificate,
  opts?: {
    typeFilter?: SubjectAlternativeGeneralName | SubjectAlternativeGeneralName[]
  }
): SubjectAlternativeName[] => {
  const typeFilter = opts?.typeFilter
    ? Array.isArray(opts.typeFilter)
      ? opts.typeFilter
      : [opts.typeFilter]
    : [SubjectAlternativeGeneralName.dnsName, SubjectAlternativeGeneralName.uniformResourceIdentifier]
  const parsedValue = certificate.extensions?.find((ext) => ext.extnID === id_SubjectAltName)?.parsedValue as AltName
  if (!parsedValue) {
    return []
  }
  const altNames = parsedValue.toJSON().altNames
  return altNames
    .filter((altName) => typeFilter.includes(altName.type))
    .map((altName) => {
      return { type: altName.type, value: altName.value } satisfies SubjectAlternativeName
    })
}
