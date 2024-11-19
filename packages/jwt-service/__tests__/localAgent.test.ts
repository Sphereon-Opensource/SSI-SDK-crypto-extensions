import { JwkDIDProvider } from '@sphereon/ssi-sdk-ext.did-provider-jwk'
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk'
import { IdentifierResolution, IIdentifierResolution } from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { SphereonKeyManager } from '@sphereon/ssi-sdk-ext.key-manager'
import { SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'
import { createAgent, IDIDManager, IKeyManager, TAgent } from '@veramo/core'
import { Entities, KeyStore, migrations, PrivateKeyStore } from '@veramo/data-store'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { SecretBox } from '@veramo/kms-local'
import { OrPromise } from '@veramo/utils'
import { Resolver } from 'did-resolver'
import { DataSource } from 'typeorm'
import { IJwtService, JwtService } from '../src'
import jwtTests from './shared/jwtServiceTest'
import { OIDFClient } from '@sphereon/ssi-sdk.oidf-client'
import { ResourceResolver } from '@sphereon/ssi-sdk.resource-resolver'

jest.setTimeout(30000)

const KMS_SECRET_KEY = 'd17c8674f5db9396f8eecccde25e882bb0336316bc411ae38dc1f3dcd7ed100f'
let databaseFile = ':memory:'
let dbConnection: OrPromise<DataSource>
let agent: TAgent<IKeyManager & IDIDManager & IIdentifierResolution & IJwtService>

const DID_METHOD = 'did:jwk'
// const PRIVATE_KEY_HEX = '7dd923e40f4615ac496119f7e793cc2899e99b64b88ca8603db986700089532b'

const jwkDIDProvider = new JwkDIDProvider({
  defaultKms: 'mem',
})

const setup = async (): Promise<boolean> => {
  const db: OrPromise<DataSource> = new DataSource({
    type: 'sqlite',
    database: databaseFile,
    synchronize: false,
    logging: ['info', 'warn'],
    entities: [...Entities],
    migrations: [...migrations],
    migrationsRun: true,
  }).initialize()
  const secretBox = new SecretBox(KMS_SECRET_KEY)

  const localAgent = createAgent<IKeyManager & IDIDManager & IIdentifierResolution & IJwtService>({
    plugins: [
      new SphereonKeyManager({
        store: new KeyStore(db),
        kms: {
          local: new SphereonKeyManagementSystem(new PrivateKeyStore(db, secretBox)),
        },
      }),
      new DIDResolverPlugin({
        resolver: new Resolver({ ...getDidJwkResolver() }),
      }),
      new DIDManager({
        providers: {
          [DID_METHOD]: jwkDIDProvider,
        },
        defaultProvider: DID_METHOD,
        store: new MemoryDIDStore(),
      }),
      new IdentifierResolution(),
      new JwtService(),
      new ResourceResolver(),
      new OIDFClient(),
    ],
  })
  agent = localAgent
  dbConnection = db
  return true
}

const tearDown = async (): Promise<boolean> => {
  await (await dbConnection).destroy()
  return true
}

const getAgent = () => agent

const testContext = { getAgent, setup, tearDown }

describe('Local integration tests', () => {
  jwtTests(testContext)
})
