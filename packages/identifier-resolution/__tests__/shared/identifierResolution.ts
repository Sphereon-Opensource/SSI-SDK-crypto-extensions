import { toJwkFromKey } from '@sphereon/ssi-sdk-ext.key-utils'
import { IDIDManager, IIdentifier, IKeyManager, TAgent } from '@veramo/core'

import { IIdentifierResolution } from '../../src'

type ConfiguredAgent = TAgent<IKeyManager & IDIDManager & IIdentifierResolution>

export default (testContext: { getAgent: () => ConfiguredAgent; setup: () => Promise<boolean>; tearDown: () => Promise<boolean> }) => {
  const kidMatcher = {
    jwk: {
      alg: 'ES256',
      crv: 'P-256',
      kty: 'EC',
    },
    key: {
      kms: 'local',
      meta: {
        algorithms: ['ES256'],
      },
      type: 'Secp256r1',
    },
    method: expect.stringMatching(/(kid)|(jwk)/),
  }

  const didMatcher = {
    controllerKeyId: expect.stringContaining('did:jwk:'),
    did: expect.stringContaining('did:jwk:'),
    identifier: {
      controllerKeyId: expect.stringContaining('did:jwk:'),
      did: expect.stringContaining('did:jwk:'),
      keys: [
        {
          kms: 'local',
          meta: {
            algorithms: ['ES256'],
          },
          type: 'Secp256r1',
        },
      ],
      provider: 'did:jwk',
      services: [],
    },
    jwk: {
      alg: 'ES256',
      crv: 'P-256',
      kty: 'EC',
    },
    key: {
      kms: 'local',
      meta: {
        algorithms: ['ES256'],
        verificationMethod: {
          controller: expect.stringContaining('did:jwk:'),
          id: expect.stringContaining('did:jwk:'),
          type: 'JsonWebKey2020',
        },
      },
      type: 'Secp256r1',
    },
    keys: [
      {
        kms: 'local',
        meta: {
          algorithms: ['ES256'],
        },
        type: 'Secp256r1',
      },
    ],
    method: 'did',
  }
  describe('identifier-resolution', () => {
    let agent: ConfiguredAgent
    let identifier: IIdentifier | undefined = undefined

    beforeAll(async () => {
      await testContext.setup().then(() => (agent = testContext.getAgent()))
      identifier = await agent.didManagerCreate({ kms: 'local' })
    })
    afterAll(testContext.tearDown)

    it('should resolve did identifier by did string', async () => {
      if (!identifier) {
        throw Error('No identifier')
      }
      console.log(didMatcher)

      const jwk = toJwkFromKey(identifier.keys[0])

      // These all contain a did or are an internal did identifier
      await expect(agent.identifierManagedGet({ identifier: identifier! })).resolves.toMatchObject(didMatcher)
      await expect(agent.identifierManagedGetByDid({ identifier: identifier! })).resolves.toMatchObject(didMatcher)
      await expect(agent.identifierManagedGet({ identifier: identifier.did })).resolves.toMatchObject(didMatcher)
      await expect(agent.identifierManagedGetByDid({ identifier: identifier.did })).resolves.toMatchObject(didMatcher)
      await expect(agent.identifierManagedGet({ identifier: identifier.controllerKeyId! })).resolves.toMatchObject(didMatcher)
      await expect(agent.identifierManagedGetByDid({ identifier: identifier.controllerKeyId! })).resolves.toMatchObject(didMatcher)

      // These are kid (actual kid and jwk thumb print)
      await expect(agent.identifierManagedGet({ identifier: identifier.keys[0].kid })).resolves.toMatchObject(kidMatcher)
      await expect(agent.identifierManagedGetByKid({ identifier: identifier.keys[0].kid })).resolves.toMatchObject(kidMatcher)
      await expect(agent.identifierManagedGet({ identifier: identifier.keys[0].meta!.jwkThumbprint! })).resolves.toMatchObject(kidMatcher)
      await expect(agent.identifierManagedGetByKid({ identifier: identifier.keys[0].meta!.jwkThumbprint! })).resolves.toMatchObject(kidMatcher)
      await expect(agent.identifierManagedGet({ identifier: jwk })).resolves.toMatchObject(kidMatcher)
      await expect(agent.identifierManagedGetByJwk({ identifier: jwk })).resolves.toMatchObject(kidMatcher)
    })
  })
}
