import { BlsKeyManagementSystem } from '../BlsKeyManagementSystem'
import { MemoryPrivateKeyStore } from '@veramo/key-manager'
import { generateBls12381G2KeyPair } from '@mattrglobal/bbs-signatures'
import { MinimalImportableKey, TKeyType } from '@veramo/core'
import * as u8a from 'uint8arrays'
describe('@sphereon/ssi-sdk-bls-kms-local', () => {
  it('should import a BLS key', async () => {
    const bls = await generateBls12381G2KeyPair()
    const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore())
    const myKey: MinimalImportableKey = {
      kms: 'local',
      type: <TKeyType>'Bls12381G2',
      privateKeyHex: Buffer.from(bls.secretKey).toString('hex'),
      publicKeyHex: Buffer.from(bls.publicKey).toString('hex'),
    }
    const key = await kms.importKey(myKey)
    expect(key.publicKeyHex).toEqual(myKey.publicKeyHex)
  })
})

describe('@veramo/kms-local x509 support', () => {
  it('should generate a managed key', async () => {
    const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore())
    // @ts-ignore
    const key = await kms.createKey({ type: 'RSA' })
    expect(key.type).toEqual('RSA')
    expect(key.publicKeyHex.length).toBeGreaterThan(320)
    expect(key.kid).toBeDefined()
    expect(key.meta?.algorithms).toEqual(['RS256', 'RS512', 'PS256', 'PS512'])
    expect(key.meta?.publicKeyPEM).toBeDefined()
    await expect(key.meta?.publicKeyJwk).toMatchObject({
      kty: 'RSA',
      e: 'AQAB',
    })
  })

  it('should import a private key', async () => {
    const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore())
    const privateKeyHex =
      '3082025b020100028181008f46d01b91eeb6fe7933b5426d82d08e725ebadfeb5b9897504c4e6d589a0f9dba88092343391ea05849f46f11d2f956c46824445ab2b8b019d9e54a3497dac562252ce57f2e698773ff12e6f930bebe1a2e0465bbaca5a3b5ed4775a013f472e5b49ab2987c5413143c4d414be07ce63a0b0e93a8de138bd46c340368cf305f0203010001028180712a896d7d52838f73c3f7c3442432fe902f6a833aaeda5389c4fb9d3a82551b4c1deeb9bf7afa49c3f285f2c4ad52ebc9ae4817055c6cac0b7f23affce2849473bb27a112362965bb4630258de3fe35a5ed8bed26ef79e5d0e0a01b925b8f2043c53b1d621a633ab027f32bf04227bdd3fbb518bfd87d559213b60c77d16b81024100f33a2ea9e6563ab67cf618a3fe4e8798dce66cd530dc4d1cb91c9a208a66898ed2b132471731ce82e0975320d99ccd150e0201af6fcb6ad01a400bdd1783cdaf02410096ccf2803b569cb4cfcebdf28424d74b0ad1cce23f75f5138b9c26987855c17a5d3f82ea3e2bee99d1a184bd89e9d627a410c2916403800d18083b6081d9a451024017ee318925d076165e5518378a5dcf998aa26132d88bd44a6f2c113e025ff448c91206105887ddf9a27f40fe8a6a9302ef4de33c8f9343ff15961794b92b8ea10240412f5c4fd3d68fac94fb701e29c2e711781ed26aa635edf741ed00bdfd9e4c2101b7d7763be3afa2ebfbdeae33b451af16fb6baf7f45081020e8460a6476d8d10240640511541bf370d6d1b3723d49ea6e7193eea225f1c8400c6e50efb75bda9a56f3569b6abd031eaa9c037d4aa934c97888c2c93eca6fc640525dd3d50d087897'
    // @ts-ignore
    const key = await kms.importKey({ kid: 'test', privateKeyHex, type: 'RSA' })
    expect(key.type).toEqual('RSA')
    expect(key.publicKeyHex).toEqual(
      '30819f300d06092a864886f70d010101050003818d00308189028181008f46d01b91eeb6fe7933b5426d82d08e725ebadfeb5b9897504c4e6d589a0f9dba88092343391ea05849f46f11d2f956c46824445ab2b8b019d9e54a3497dac562252ce57f2e698773ff12e6f930bebe1a2e0465bbaca5a3b5ed4775a013f472e5b49ab2987c5413143c4d414be07ce63a0b0e93a8de138bd46c340368cf305f0203010001'
    )
    expect(key.kid).toEqual('test')
    expect(key.meta?.algorithms).toEqual(['RS256', 'RS512', 'PS256', 'PS512'])

    expect(key.meta?.publicKeyPEM).toBeDefined()
    await expect(key.meta?.publicKeyJwk).toMatchObject({
      kty: 'RSA',
      e: 'AQAB',
    })
  })

  it('should sign input data', async () => {
    const kms = new BlsKeyManagementSystem(new MemoryPrivateKeyStore())
    const privateKeyHex =
      '3082025b020100028181008f46d01b91eeb6fe7933b5426d82d08e725ebadfeb5b9897504c4e6d589a0f9dba88092343391ea05849f46f11d2f956c46824445ab2b8b019d9e54a3497dac562252ce57f2e698773ff12e6f930bebe1a2e0465bbaca5a3b5ed4775a013f472e5b49ab2987c5413143c4d414be07ce63a0b0e93a8de138bd46c340368cf305f0203010001028180712a896d7d52838f73c3f7c3442432fe902f6a833aaeda5389c4fb9d3a82551b4c1deeb9bf7afa49c3f285f2c4ad52ebc9ae4817055c6cac0b7f23affce2849473bb27a112362965bb4630258de3fe35a5ed8bed26ef79e5d0e0a01b925b8f2043c53b1d621a633ab027f32bf04227bdd3fbb518bfd87d559213b60c77d16b81024100f33a2ea9e6563ab67cf618a3fe4e8798dce66cd530dc4d1cb91c9a208a66898ed2b132471731ce82e0975320d99ccd150e0201af6fcb6ad01a400bdd1783cdaf02410096ccf2803b569cb4cfcebdf28424d74b0ad1cce23f75f5138b9c26987855c17a5d3f82ea3e2bee99d1a184bd89e9d627a410c2916403800d18083b6081d9a451024017ee318925d076165e5518378a5dcf998aa26132d88bd44a6f2c113e025ff448c91206105887ddf9a27f40fe8a6a9302ef4de33c8f9343ff15961794b92b8ea10240412f5c4fd3d68fac94fb701e29c2e711781ed26aa635edf741ed00bdfd9e4c2101b7d7763be3afa2ebfbdeae33b451af16fb6baf7f45081020e8460a6476d8d10240640511541bf370d6d1b3723d49ea6e7193eea225f1c8400c6e50efb75bda9a56f3569b6abd031eaa9c037d4aa934c97888c2c93eca6fc640525dd3d50d087897'
    const data = u8a.fromString('test', 'utf-8')

    // @ts-ignore
    const key = await kms.importKey({ kid: 'test', privateKeyHex, type: 'RSA' })
    const signature = await kms.sign({ keyRef: key, data, algorithm: 'RS256' })
    expect(signature).toEqual(
      'RJfBIpGscKKrWNNVau5zNWwQHOKCOWnh5f1VH7H7rwJcwrroHBpqNnf1EqA51nzpSlzynsQ69BLQkcUX3Yq2VeRPUVazOWAJ_xa9EIRcbpIjxi33zH_DjDdOQnre8WB1KNCg_Nkql5KjCmwGRTjCqBDRkNXPmfRoUoG3XKTSSW4='
    )
  })
})
