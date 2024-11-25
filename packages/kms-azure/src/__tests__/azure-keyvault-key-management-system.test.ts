import {com} from "@sphereon/kmp-crypto-kms-azure";
import {AzureKeyVaultKeyManagementSystem} from '../AzureKeyVaultKeyManagementSystem'
import * as process from "node:process";

describe('Key creation', () => {
    const id = "azure-keyvault-test"

    const keyVaultUrl = process.env.AZURE_KEYVAULT_URL
    const tenantId = process.env.AZURE_KEYVAULT_TENANT_ID
    const keyVaultClientId = process.env.AZURE_KEYVAULT_CLIENT_ID
    const keyVaultClientSecret = process.env.AZURE_KEYVAULT_CLIENT_SECRET

    if (!keyVaultUrl || !tenantId || !keyVaultClientId || !keyVaultClientSecret) {
        throw new Error("Missing Azure KeyVault test environment variables")
    }

    const credentialOptions = new com.sphereon.crypto.kms.azure.CredentialOpts(
        com.sphereon.crypto.kms.azure.CredentialMode.SERVICE_CLIENT_SECRET,
        new com.sphereon.crypto.kms.azure.SecretCredentialOpts(
            keyVaultClientId,
            keyVaultClientSecret
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

        const verified = await kms.verify({
            data,
            signature,
            keyRef: {kid: key.kid}
        })

        expect(verified).toBeTruthy()
    })

    it('should not verify wrong sign with a Secp256r1 key', async () => {
        const key = await kms.createKey({
            type: 'Secp256r1', meta: {
                keyAlias: `test-key-${crypto.randomUUID()}`
            }
        })

        const data = new TextEncoder().encode('test')

        const verified = await kms.verify({
            data,
            signature: "b0d1e9621d5e35206e982e1db5b15877565e76494d90f2227cc1d14961c15c1fa37a9c197a9c3d22ca94d665f14a3670bb84e1af2641cf09a08fa56f467de541",
            keyRef: {kid: key.kid}
        })

        expect(verified).toBeFalsy()
    })
})
