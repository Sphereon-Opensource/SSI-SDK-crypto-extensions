import { generatePrivateKeyHex, padLeft, validateX509CertificateChain } from '../src'
import { Key } from '../src'

describe('functions: key generator', () => {
  it('Secp256k1 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Secp256k1)
    const key2 = await generatePrivateKeyHex(Key.Secp256k1)
    const key3 = await generatePrivateKeyHex(Key.Secp256k1)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Secp256k1 should result in hex length 64', async () => {
    expect((await generatePrivateKeyHex(Key.Secp256k1)).length).toBe(64)
  })

  it('Secp256r1 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Secp256r1)
    const key2 = await generatePrivateKeyHex(Key.Secp256r1)
    const key3 = await generatePrivateKeyHex(Key.Secp256r1)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Secp256r1 should result in hex length 64', async () => {
    expect((await generatePrivateKeyHex(Key.Secp256r1)).length).toBe(64)
  })

  it('Ed25519 should generate random keys', async () => {
    const key1 = await generatePrivateKeyHex(Key.Ed25519)
    const key2 = await generatePrivateKeyHex(Key.Ed25519)
    const key3 = await generatePrivateKeyHex(Key.Ed25519)
    expect(key1).toBeDefined()
    expect(key2).toBeDefined()
    expect(key3).toBeDefined()
    expect(key1).not.toBe(key2)
    expect(key2).not.toBe(key3)
  })
  it('Ed25519 should result in hex length 128', async () => {
    expect((await generatePrivateKeyHex(Key.Ed25519)).length).toBe(128)
  })
})
describe('functions: Leftpad', () => {
  it('should pad left to 64 chars when 62 chars are present', () => {
    const data = '2df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`00${data}`)
  })

  it('should not pad left to 64 chars when 64 chars are present', () => {
    const data = '002df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`${data}`)
  })

  it('should not pad left to 64 chars when more than 64 chars are present', () => {
    const data = '12345002df693fc990b11367d8d1613b780fdd35876493e5e2517c4e1ada0ecfd8aa1'
    const result = padLeft({ data, size: 64, padString: '0' })
    expect(result).toEqual(`${data}`)
  })
})

const sphereonCA =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIICCDCCAa6gAwIBAgITAPMgqwtYzWPBXaobHhxG9iSydTAKBggqhkjOPQQDAjBa\n' +
  'MQswCQYDVQQGEwJOTDEkMCIGA1UECgwbU3BoZXJlb24gSW50ZXJuYXRpb25hbCBC\n' +
  'LlYuMQswCQYDVQQLDAJJVDEYMBYGA1UEAwwPY2Euc3BoZXJlb24uY29tMB4XDTI0\n' +
  'MDcyODIxMjY0OVoXDTM0MDcyODIxMjY0OVowWjELMAkGA1UEBhMCTkwxJDAiBgNV\n' +
  'BAoMG1NwaGVyZW9uIEludGVybmF0aW9uYWwgQi5WLjELMAkGA1UECwwCSVQxGDAW\n' +
  'BgNVBAMMD2NhLnNwaGVyZW9uLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n' +
  'BEiA0KeESSNrOcmCDga8YsBkUTgowZGwqvL2n91JUpAMdRSwvlVFdqdiLXnk2pQq\n' +
  'T1vZnDG0I+x+iz2EbdsG0aajUzBRMB0GA1UdDgQWBBTnB8pdlVz5yKD+zuNkRR6A\n' +
  'sywywTAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgwBgYEVR0lADAPBgNVHRMBAf8E\n' +
  'BTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIHH7ie1OAAbff5262rzZVQa8J9zENG8A\n' +
  'QlHHFydMdgaXAiEA1Ib82mhHIYDziE0DDbHEAXOs98al+7dpo8fPGVGTeKI=\n' +
  '-----END CERTIFICATE-----'

const walletPEM =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIDwzCCA2mgAwIBAgISKDZBYxEV61yg6xUjrxcTZ17WMAoGCCqGSM49BAMCMFox\n' +
  'CzAJBgNVBAYTAk5MMSQwIgYDVQQKDBtTcGhlcmVvbiBJbnRlcm5hdGlvbmFsIEIu\n' +
  'Vi4xCzAJBgNVBAsMAklUMRgwFgYDVQQDDA9jYS5zcGhlcmVvbi5jb20wHhcNMjQw\n' +
  'NzI4MjAwMjQ0WhcNMjQxMDI2MjIwMjQ0WjAjMSEwHwYDVQQDDBh3YWxsZXQudGVz\n' +
  'dC5zcGhlcmVvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE\n' +
  'NxhvsnlZr48eRNYk90qv80Xokko2mBWHLQVGwbJHIjkKhPV7aC1ezcaMHGtvLwhq\n' +
  'EvnI+xefeMYUlw1sFhAqGq3UnhqwYLNm6dSIQe1pgHP74nfX06hfgvdGmfZkVxMM\n' +
  'XyxK5gasFg5TuAIsEv8wsqf0vFF2SGKaVFmN5qH4FQvSUtOtJAWQKsee1NSGVkpK\n' +
  't/POXrG8LidXlpYj17Sh0P8YoFT4DEEj8ZAm6r1W/SDlaZywvEmNLr1ld+MLdm1i\n' +
  'UbtjC/kqB3wDbu2W8T9Yz6jPOsJy3nv/tHiB4Yh8fF9R7+18tZiIt+P+awJrza1D\n' +
  'w1GbuVBTKx00KUtZ2CzlAgMBAAGjggF5MIIBdTAdBgNVHQ4EFgQUuCN6sAJCz64f\n' +
  'CZ3js3ITfKQzFF4wHwYDVR0jBBgwFoAU5wfKXZVc+cig/s7jZEUegLMsMsEwYQYI\n' +
  'KwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vZXUuY2VydC5lemNhLmlv\n' +
  'L2NlcnRzL2RhYTFiNGI0LTg1ZmQtNGJhNC1iOTZiLTMzMmFkZDg5OWNlOS5jZXIw\n' +
  'HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMD4GA1UdEQQ3MDWCGHdhbGxl\n' +
  'dC50ZXN0LnNwaGVyZW9uLmNvbYIZZnVua2Uud2FsbGV0LnNwaGVyZW9uLmNvbTAO\n' +
  'BgNVHQ8BAf8EBAMCBLAwYQYDVR0fBFowWDBWoFSgUoZQaHR0cDovL2V1LmNybC5l\n' +
  'emNhLmlvL2NybC8yY2RmN2M1ZS1iOWNkLTQzMTctYmI1Ni0zODZkMjQ0MzgwZTIv\n' +
  'Y2FzcGhlcmVvbmNvbS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIgfY5MD3fWNf8Q0j5C\n' +
  'mYHDHcwOkwygISpMDOh9K5DBBV4CIQCuQ3nToCr/II2WVsAqRXFeZup08fzKLrU2\n' +
  'KZxmdxeoew==\n' +
  '-----END CERTIFICATE-----'

const externalTestCert =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIDezCCAmOgAwIBAgIhAIhyE4lj2NAOEV7WfxQzdUfai0kmzBvHuNcDacKoZdoY\n' +
  'MA0GCSqGSIb3DQEBBQUAMFAxCTAHBgNVBAYTADEJMAcGA1UECgwAMQkwBwYDVQQL\n' +
  'DAAxDTALBgNVBAMMBHRlc3QxDzANBgkqhkiG9w0BCQEWADENMAsGA1UEAwwEdGVz\n' +
  'dDAeFw0yNDA4MDYxNjI4NTdaFw0zNDA4MDcxNjI4NTdaMEExCTAHBgNVBAYTADEJ\n' +
  'MAcGA1UECgwAMQkwBwYDVQQLDAAxDTALBgNVBAMMBHRlc3QxDzANBgkqhkiG9w0B\n' +
  'CQEWADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI/7Qxc3dcOCmL6Q\n' +
  'zsnVAtWfNnLNwBOf+gAURg4kDHoFlc8bfa52uiB+ryKOXMO1xunhE+dEYZYHjaHM\n' +
  'jum6cH7MpmWPDhI01UhiOxY+nJ9xDJE81B/lTbI8FEZ5Z1roqGPQA2es6yBlO2i9\n' +
  'paa6RDQg9xJyqbLl1Y2xM6t16xBM20EIefGJGCpMkDryiF9QiFDoxivZI8SuOfC4\n' +
  '+avmNvQ2PuWaPjELoAe/4I9qHmXvUZSJZxpmnqR1I19+ySaQ8huVDI8UqCkG0/jB\n' +
  'n101s7emyFlkuMmr2zLV48/ckHVFZXpjBiAaCZJlHNA9kMfNUwEaWNobiNemIVLM\n' +
  'rLn4KN8CAwEAAaNPME0wHQYDVR0OBBYEFN+fvlWXGUPNLtSigoSfnnJV8O7cMB8G\n' +
  'A1UdIwQYMBaAFN+fvlWXGUPNLtSigoSfnnJV8O7cMAsGA1UdEQQEMAKCADANBgkq\n' +
  'hkiG9w0BAQUFAAOCAQEAj4HlAZ1rpzoa2m/wbHbZsLlmfV+3GH6Cf/BBP4HeY/p2\n' +
  'M5bDDeAwKSi3vF+ZlpdkwDiXbHxNVPtrhNAD9o2Oe6NicuhnTTMzdDUVvRPzfRkw\n' +
  'zRUgyEcQUUShoma7K2EKG4HgHKZ5xCPvp0RQ8qwN4yrCm85HXHemdINHLrxOGBuX\n' +
  'p9K4zhfl3aHn4PMGGN0KG/dxmhFs4475dHnF2KeyhrDVpoqKVY5NFhuNXF9MiRnG\n' +
  'cS4jCEbpYwEhSlIxCHCWQgkFPohtg+aR/YtOwm0xNsaXdw/jYk0j2nin3AawdhBv\n' +
  'opkupVtRIrPA4fHKmUknr6WK1h+sS4qKhPsLSBGGkQ==\n' +
  '-----END CERTIFICATE-----\n'

describe('functions: validateX5cCertificateChain', () => {
  const validChain = [walletPEM, sphereonCA]

  const invalidChain = [externalTestCert, walletPEM, sphereonCA]

  it('should validate a valid certificate chain', async () => {
    const result = await validateX509CertificateChain({ chain: [walletPEM, sphereonCA] })
    expect(result).toMatchObject({
      critical: false,
      error: false,
      message: 'Certificate chain was valid',
    })
  })

  it('should not validate an invalid certificate chain', async () => {
    const result = await validateX509CertificateChain({ chain: invalidChain })
    expect(result).toMatchObject({
      critical: true,
      error: true,
      message: 'Calculated chain length 1 is smaller than provided chain length 3.',
    })
  })

  it('should throw an error for an empty chain', async () => {
    await expect(validateX509CertificateChain({ chain: [] })).resolves.toMatchObject({
      critical: true,
      error: true,
      message: 'Certificate chain in DER or PEM format must not be empty',
    })
  })

  it('should validate with a trusted root certificate', async () => {
    const result = await validateX509CertificateChain({ chain: validChain, trustedCerts: [sphereonCA] })
    expect(result).toMatchObject({
      critical: false,
      error: false,
      message: 'Certificate chain was valid',
    })
  })

  it('should not validate with an untrusted root certificate', async () => {
    const result = await validateX509CertificateChain({ chain: validChain, trustedCerts: [externalTestCert] })
    expect(result).toMatchObject({
      critical: true,
      error: true,
      message: 'Root certificate nr 2, C=NL, O=Sphereon International B.V., OU=IT, CN=ca.sphereon.com was not found in trusted certificates',
    })
  })

  it('should validate with a valid verification date', async () => {
    const verificationDate = new Date('2023-06-01')
    const result = await validateX509CertificateChain({ chain: validChain, verificationTime: verificationDate })
    expect(result).toMatchObject({
      critical: true,
      error: true,
      message: 'Certificate nr 1, CN=wallet.test.sphereon.com was not valid',
    })
  })

  it('should validate with a verification date after expiry', async () => {
    const verificationDate = new Date('2033-06-01')
    const result = await validateX509CertificateChain({ chain: validChain, verificationTime: verificationDate })
    expect(result).toMatchObject({
      critical: true,
      error: true,
      message: 'Certificate nr 1, CN=wallet.test.sphereon.com was not valid',
    })
  })

  it('should validate with a verification date before becoming valid', async () => {
    const verificationDate = new Date('2013-06-01')
    const result = await validateX509CertificateChain({ chain: validChain, verificationTime: verificationDate })
    expect(result).toMatchObject({
      critical: true,
      error: true,
      message: 'Certificate nr 1, CN=wallet.test.sphereon.com was not valid',
    })
  })
})
