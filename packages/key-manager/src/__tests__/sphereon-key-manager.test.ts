import { SphereonKeyManager } from '../agent/SphereonKeyManager'
import { MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { IKey, ManagedKeyInfo } from '@veramo/core'
import { generateBls12381G2KeyPair } from '@mattrglobal/bbs-signatures'
import { SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'

describe('@sphereon/ssi-sdk-ext.kms-local', () => {
  let bls: { publicKey: Uint8Array; secretKey: Uint8Array }
  let kms: SphereonKeyManager

  beforeAll(async () => {
    bls = await generateBls12381G2KeyPair()
    kms = new SphereonKeyManager({
      store: new MemoryKeyStore(),
      kms: {
        local: new SphereonKeyManagementSystem(new MemoryPrivateKeyStore()),
      },
    })
  })

  it('should import a BLS key', async () => {
    const myKey = {
      type: 'Bls12381G2',
      privateKeyHex: Buffer.from(bls.secretKey).toString('hex'),
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
        algorithms: ['BLS'],
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
          algorithms: ['BLS'],
        },
      })
    )
  })

  //TODO need to update Veramo core to add the data array allowed by bls signer
  it('should sign with a BLS key', async () => {
    const key: IKey = (await kms.keyManagerGet({ kid: Buffer.from(bls.publicKey).toString('hex') })) as IKey
    await expect(
      kms.keyManagerSign({
        keyRef: key.kid,
        data: ['test data'] as any,
      })
    ).resolves.toBeDefined()
  })

  it('should delete a bls key', async () => {
    await expect(kms.keyManagerDelete({ kid: Buffer.from(bls.publicKey).toString('hex') })).resolves.toBeTruthy()
  })

  it('should get all the keys in the sphereon key manager', async () => {
    const myKey = {
      type: 'Bls12381G2',
      privateKeyHex: Buffer.from(bls.secretKey).toString('hex'),
      publicKeyHex: Buffer.from(bls.publicKey).toString('hex'),
    }
    await kms.keyManagerImport({
      kid: myKey.publicKeyHex,
      privateKeyHex: myKey.privateKeyHex,
      publicKeyHex: myKey.publicKeyHex,
      kms: 'local',
      type: 'Bls12381G2',
    })
    const keys: ManagedKeyInfo[] = await kms.keyManagerListKeys()
    keys.forEach((key) => {
      expect(key['privateKeyHex' as keyof ManagedKeyInfo]).toBeUndefined()
    })
  })

  afterAll(async () => {
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })
})
