import { Resolver } from 'did-resolver'
import { DID_LD_JSON, getResolver } from '../index'
import * as fs from 'fs'

describe('@sphereon/ssi-sdk-ext.did-resolver-ebsi', () => {
  it('should resolve a v1 did:ebsi against the default registry', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const resolutionResult = await resolver.resolve('did:ebsi:z25gUx2D5Ujb6eZcmQEnertx#5jOg2ai976NEo_UKDCDHqDzO1vBx2RQJ_9ZuyZLqSCs', {
      accept: DID_LD_JSON,
    })
    expect(resolutionResult.didDocument).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/ebsiv1_did_doc.json`, { encoding: 'utf-8' })))
  })
  it('should resolve a v1 did:ebsi against a configured registry', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const resolutionResult = await resolver.resolve('did:ebsi:z25gUx2D5Ujb6eZcmQEnertx#5jOg2ai976NEo_UKDCDHqDzO1vBx2RQJ_9ZuyZLqSCs', {
      accept: DID_LD_JSON,
      registry: 'https://api-pilot.ebsi.eu/did-registry/v4',
    })
    expect(resolutionResult.didDocument).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/ebsiv1_did_doc.json`, { encoding: 'utf-8' })))
  })

  it('should not resolve a v1 did:ebsi against a non-existing registry', async () => {
    const resolver = new Resolver({ ...getResolver() })
    await expect(
      resolver.resolve('did:ebsi:z25gUx2D5Ujb6eZcmQEnertx#5jOg2ai976NEo_UKDCDHqDzO1vBx2RQJ_9ZuyZLqSCs', {
        accept: DID_LD_JSON,
        registry: 'http://127.0.0.1:9993',
        noFallbackRegistries: true,
        noEnvVarRegistry: true,
      })
    ).resolves.toEqual({
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
        error: 'invalidDid',
        message: 'Error: Could not resolve DID did:ebsi:z25gUx2D5Ujb6eZcmQEnertx using registries: ["http://127.0.0.1:9993"]',
      },
    })
  })
})
