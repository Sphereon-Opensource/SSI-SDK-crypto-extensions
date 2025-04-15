import { createAgent, IDIDManager, IIdentifier, IKeyManager } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { SphereonKeyManager } from '@sphereon/ssi-sdk-ext.key-manager'
import { SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'
import { MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { OydDIDProvider } from '../src'
import { DefaultOydCmsmCallbacks } from '../src/oyd-did-provider'

const DID_METHOD = 'did:oyd'


const keyManager = new SphereonKeyManager({
  store: new MemoryKeyStore(),
  kms: {
    mem: new SphereonKeyManagementSystem(new MemoryPrivateKeyStore()),
  },
})
const oydDIDProvider = new OydDIDProvider({
  defaultKms: 'mem',
  clientManagedSecretMode: new DefaultOydCmsmCallbacks(keyManager)
})
const agent = createAgent<IKeyManager & IDIDManager>({
  plugins: [
    keyManager,
    new DIDManager({
      providers: {
        [DID_METHOD]: oydDIDProvider,
      },
      defaultProvider: DID_METHOD,
      store: new MemoryDIDStore(),
    }),
  ],
})

describe('@sphereon/did-provider-oyd', () => {
  it('should create identifier', async () => {
    const identifier: IIdentifier = await agent.didManagerCreate()

    expect(identifier).toBeDefined()
    expect(identifier.keys.length).toBe(1)
  })

  it('should create identifier with CMSM', async () => {
    const identifier: IIdentifier = await agent.didManagerCreate( { options: { keyType: 'Secp256r1', kid: 'test', cmsm: {enabled: true, create: true} } })

    console.log(identifier)
    expect(identifier).toBeDefined()
    expect(identifier.keys.length).toBe(1)
  })

})
