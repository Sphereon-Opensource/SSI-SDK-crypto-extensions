import {com} from "@sphereon/kmp-crypto-kms-azure";
import {AzureKeyVaultKeyManagementSystem} from '../AzureKeyVaultKeyManagementSystem'
import * as process from "node:process";

describe('Key creation', () => {
    const id = "azure-keyvault-test"
    const keyVaultUrl = process.env.AZURE_KEYVAULT_TEST_VAULT_URL!!
    const tenantId = process.env.AZURE_KEYVAULT_TEST_TENANT_ID!!
    const credentialOptions = new com.sphereon.crypto.kms.azure.CredentialOpts(
        com.sphereon.crypto.kms.azure.CredentialMode.SERVICE_CLIENT_SECRET,
        new com.sphereon.crypto.kms.azure.SecretCredentialOpts(
            process.env.AZURE_KEYVAULT_TEST_CLIENT_ID!!,
            process.env.AZURE_KEYVAULT_TEST_CLIENT_SECRET!!
        )
    )

    const azureKeyVaultClientConfig = new com.sphereon.crypto.kms.azure.AzureKeyVaultClientConfig(
        id,
        keyVaultUrl,
        tenantId,
        credentialOptions
    )

    const kms = new AzureKeyVaultKeyManagementSystem(azureKeyVaultClientConfig)

    it('should create a Secp256r1 key', async () => {
        const key = await kms.createKey({
            type: 'Secp256r1', meta: {
                keyAlias: `test-key-${crypto.randomUUID()}`
            }
        })

        expect(key.type).toEqual('Secp256r1')
        expect(key?.meta?.jwkThumbprint).toBeDefined()
        expect(key?.meta?.algorithms).toContain('ES256')
    })

    it('should create sign and verify with a Secp256r1 key', async () => {
        const key = await kms.createKey({
            type: 'Secp256r1', meta: {
                keyAlias: `test-key-${crypto.randomUUID()}`
            }
        })

        const data = new TextEncoder().encode('test')
        const signature = await kms.sign({
            data,
            keyRef: {kid: key.kid}
        })

        console.log('signature', signature)

        expect(signature).toBeDefined()

        const verified = await kms.verify({
            data,
            signature,
            keyRef: {kid: key.kid}
        })

        console.log('verified', verified)

        expect(verified).toBeTruthy()
    })
})
