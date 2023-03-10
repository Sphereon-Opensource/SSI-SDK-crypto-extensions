import { BlsKeyManager } from '../agent/BlsKeyManager'
import { MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { IKey } from '@veramo/core'
import { BlsKeyManagementSystem } from '../../../bls-kms-local/src'
import { generateBls12381G2KeyPair } from '../../../bls-kms-local/src/BlsKeyManagementSystem'

describe('@sphereon/bls-kms-local', () => {
  let bls: { publicKey: Uint8Array; privateKey?: Uint8Array }
  let kms: BlsKeyManager

  beforeAll(async () => {
    bls = await generateBls12381G2KeyPair()
    kms = new BlsKeyManager({
      store: new MemoryKeyStore(),
      kms: {
        local: new BlsKeyManagementSystem(new MemoryPrivateKeyStore()),
      },
    })
  })

  it('should import a BLS key', async () => {
    const myKey = {
      type: 'Bls12381G2',
      privateKeyHex: Buffer.from(bls.privateKey!).toString('hex'),
      publicKeyHex: Buffer.from(bls.publicKey).toString('hex'),
    }
    const key = await kms.keyManagerImport({
      kid: myKey.publicKeyHex,
      privateKeyHex: myKey.privateKeyHex,
      publicKeyHex: myKey.publicKeyHex,
      kms: 'local',
      type: 'Bls12381G2',
    })
    expect(key).toEqual({
      kid: myKey.publicKeyHex,
      kms: 'local',
      meta: {
        algorithms: ['BLS', 'Bls12381G2', 'Bls12381G2Key2020'],
      },
      publicKeyHex: myKey.publicKeyHex,
      type: 'Bls12381G2',
    })
  })

  it('should get key management systems', async () => {
    await expect(kms.keyManagerGetKeyManagementSystems()).resolves.toEqual(['local'])
  })

  it('should get BLS key', async () => {
    await expect(kms.keyManagerGet({ kid: Buffer.from(bls.publicKey).toString('hex') }))
  })

  it('should create a BLS key', async () => {
    await expect(
      kms.keyManagerCreate({
        kms: 'local',
        type: 'Bls12381G2',
      })
    ).resolves.toEqual(
      expect.objectContaining({
        kms: 'local',
        type: 'Bls12381G2',
        meta: {
          algorithms: ['BLS', 'Bls12381G2', 'Bls12381G2Key2020'],
        },
      })
    )
  })

  it('should sign with a BLS key', async () => {
    const key: IKey = (await kms.keyManagerGet({ kid: Buffer.from(bls.publicKey).toString('hex') })) as IKey
    await expect(
      kms.keyManagerSign({
        keyRef: key.kid,
        data: 'test data',
      })
    ).resolves.toBeDefined()
  })

  it('should delete a bls key', async () => {
    await expect(kms.keyManagerDelete({ kid: Buffer.from(bls.publicKey).toString('hex') })).resolves.toBeTruthy()
  })

  afterAll(async () => {
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })
})
