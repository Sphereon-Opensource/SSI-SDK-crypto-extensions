import {
  ExternalIdentifierOIDFEntityIdResult,
  ExternalIdentifierResult,
  IIdentifierResolution,
} from '../../../identifier-resolution/src/types' // FIXME fix when new types have been absorbed throughout ssi-sdk
import { IKeyManager, TAgent } from '@veramo/core'
import { IJwtService } from '@sphereon/ssi-sdk-ext.jwt-service'
import { describe } from 'node:test'

type ConfiguredAgent = TAgent<IKeyManager & IIdentifierResolution & IJwtService>

export default (testContext: {
    getAgent: () => ConfiguredAgent;
    setup: () => Promise<boolean>;
    tearDown: () => Promise<boolean>
}) => {
    let agent: ConfiguredAgent
    // let key: IKey

    // tbe above key as hex
    const privateKeyHex = '8E9B109E719098BF980487DF1F5D77E9CB29606EBED2263B5F57C213DF84F4B2'.toLowerCase()

    beforeAll(async () => {
        await testContext.setup().then(() => (agent = testContext.getAgent()))
        await agent.keyManagerImport({kid: 'test', type: 'Secp256r1', kms: 'local', privateKeyHex})
    })
    afterAll(testContext.tearDown)

    

  describe('oidf-identifier-resolution', () => {
    it('should resolve OIDF entity ID against multiple trust anchors', async () => {
      const EXAMPLE_ENTITY_ID = 'https://agent.findynet.demo.sphereon.com/oid4vci'
      const result: ExternalIdentifierResult = await agent.identifierExternalResolve({
        identifier: EXAMPLE_ENTITY_ID,
        trustAnchors: ['https://federation.demo.sphereon.com', 'https://federation.dev.findy.fi']
      })

      expect(result).toBeDefined()
      expect(result.method).toEqual('entity_id')

      if (result.method === 'entity_id') {
        const entityResult = result as ExternalIdentifierOIDFEntityIdResult
        expect(entityResult.trustedAnchors).toBeDefined()

        expect(entityResult.trustedAnchors['https://federation.demo.sphereon.com'])
          .toEqual('036f147e164a6b2ae860330b75bb54243b028086b4297a8d663bb4afe4080afec7')

        expect(entityResult.errorList).toBeDefined()
        if(entityResult.errorList) {
          expect(entityResult.errorList['https://federation.dev.findy.fi'])
            .toEqual('A Trust chain could not be established')
        }

        expect(Array.isArray(entityResult.jwks)).toBe(true)
        expect(entityResult.jwks).toHaveLength(1)

        const jwk = entityResult.jwks[0]
        expect(jwk.jwkThumbprint).toEqual('PjWRF5oJSGKQQaf_NPMndBA528S_Ulqcu6E_ZWZkkWY')
        
        expect(entityResult.trustEstablished).toBeTruthy()
      }
    })
  })
}
