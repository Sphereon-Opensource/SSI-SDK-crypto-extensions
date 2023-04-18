import { Resolver } from 'did-resolver'
import { DID_LD_JSON, getResolver } from '../index'
import * as fs from 'fs'

describe('@sphereon/ssi-sdk-ext.did-resolver-ebsi', () => {
  it('should resolve a v1 did:ebsi', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const resolutionResult = await resolver.resolve('did:ebsi:z25gUx2D5Ujb6eZcmQEnertx#5jOg2ai976NEo_UKDCDHqDzO1vBx2RQJ_9ZuyZLqSCs', {
      accept: DID_LD_JSON,
    })
    expect(resolutionResult.didDocument).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/ebsiv1_did_doc.json`, { encoding: 'utf-8' })))
  })
})
