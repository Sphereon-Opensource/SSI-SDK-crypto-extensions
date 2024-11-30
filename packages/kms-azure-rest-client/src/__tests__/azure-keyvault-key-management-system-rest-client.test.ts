import {AzureKeyVaultKeyManagementSystemRestClient} from '../AzureKeyVaultKeyManagementSystemRestClient'

describe('Key creation', () => {
    const applicationId = 'azure-keyvault-rest-client-test'

    const keyClient = new AzureKeyVaultKeyManagementSystemRestClient(
        {
            applicationId,
            vaultUrl: process.env.AZURE_KEYVAULT_REST_CLIENT_URL,
            apiKey: process.env.AZURE_KEYVAULT_REST_CLIENT_API_KEY
        }
    )

    it('should create a Secp256r1 key', async () => {
        const key = await keyClient.createKey({
            type: 'Secp256r1',
            meta: {
                keyAlias: `test-key-${crypto.randomUUID()}`,
            },
        })

        expect(key.type).toEqual('Secp256r1')
        expect(key?.meta?.jwkThumbprint).toBeDefined()
        expect(key?.meta?.algorithms).toContain('P-256')
    })

    it('should create sign and verify with a Secp256r1 key', async () => {
        const alias = `test-key-${crypto.randomUUID()}`
        await keyClient.createKey({
            type: 'Secp256r1',
            meta: {
                keyAlias: alias,
            },
        })

        const data = new TextEncoder().encode('test')
        const signature = await keyClient.sign({
            data,
            keyRef: {kid: alias},
        })

        const verified = await keyClient.verify({
            data,
            signature,
            keyRef: {kid: alias},
        })

        expect(verified).toBeTruthy()
    })

    it('should not verify wrong sign with a Secp256r1 key', async () => {
        const alias = `test-key-${crypto.randomUUID()}`
        await keyClient.createKey({
            type: 'Secp256r1',
            meta: {
                keyAlias: alias,
            },
        })

        const data = new TextEncoder().encode('test')

        const verified = await keyClient.verify({
            data,
            signature: "a572cd0aecaa9a2bf7635d7ed841928aa945c0a1e8b159972d68c54f31a3486fa092ae5789a620262f0168e4b49d9fdaa8f93d28c202d4969f1d0caf5ec61cda",
            keyRef: {kid: alias},
        })

        expect(verified).toBeFalsy()
    })
})
