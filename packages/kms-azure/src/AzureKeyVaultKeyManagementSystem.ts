import {AzureKeyVaultCryptoProvider, com} from '@sphereon/kmp-crypto-kms-azure'
import {IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType} from '@veramo/core'
import {AbstractKeyManagementSystem} from '@veramo/key-manager'
import {KeyMetadata} from './index'
import AzureKeyVaultClientConfig = com.sphereon.crypto.kms.azure.AzureKeyVaultClientConfig;
import SignatureAlgorithm = com.sphereon.crypto.generic.SignatureAlgorithm;
import KeyOperations = com.sphereon.crypto.generic.KeyOperations;
import JwkUse = com.sphereon.crypto.jose.JwkUse;
import ManagedKeyPair = com.sphereon.crypto.generic.ManagedKeyPair;

export class AzureKeyVaultKeyManagementSystem extends AbstractKeyManagementSystem {
    private client: AzureKeyVaultCryptoProvider

    constructor(private config: AzureKeyVaultClientConfig) {
        super()

        this.client = new AzureKeyVaultCryptoProvider(this.config)
    }

    async createKey(args: { type: TKeyType; meta?: KeyMetadata }): Promise<ManagedKeyInfo> {
        const {type, meta} = args

        if (meta === undefined || !('keyAlias' in meta)) {
            return Promise.reject(Error('a unique keyAlias field is required for AzureKeyVaultKMS'))
        }

        const options = new AzureKeyVaultCryptoProvider.GenerateKeyRequest(
            meta.keyAlias,
            'keyUsage' in meta ? this.mapKeyUsage(meta.keyUsage) : JwkUse.sig,
            'keyOperations' in meta ? this.mapKeyOperations(meta.keyOperations as string[]) : [KeyOperations.SIGN],
            this.mapKeyTypeToSignatureAlgorithm(type)
        )
        const key: ManagedKeyPair = await this.client.generateKeyAsync(options)

        console.log('key', key)

        // @ts-ignore
        return key.joseToManagedKeyInfo()
    }

    async sign(args: {
        keyRef: Pick<IKey, 'kid'>;
        data: Uint8Array;
        [x: string]: any
    }): Promise<string> {
        if (!args.keyRef) {
            throw new Error('key_not_found: No key ref provided')
        }
        const key = await this.client.fetchKeyAsync(args.keyRef.kid)
        return (await this.client.createRawSignatureAsync({
            keyInfo: key,
            input: new Int8Array(args.data),
            requireX5Chain: false
        })).toString()
    }

    async verify(args: {
        keyRef: Pick<IKey, 'kid'>;
        algorithm?: string;
        data: Uint8Array;
        [x: string]: any
    }): Promise<string> {
        if (!args.keyRef) {
            throw new Error('key_not_found: No key ref provided')
        }

        throw new Error('!!! Implement this method !!!')
    }

    sharedSecret(args: {
        myKeyRef: Pick<IKey, 'kid'>;
        theirKey: Pick<IKey, 'publicKeyHex' | 'type'>
    }): Promise<string> {
        throw new Error('sharedSecret is not implemented for AzureKeyVaultKMS.')
    }

    async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
        throw new Error('importKey is not implemented for AzureKeyVaultKMS.')
    }

    async deleteKey({kid}: { kid: string }): Promise<boolean> {
        throw new Error('deleteKey is not implemented for AzureKeyVaultKMS.')
    }

    async listKeys(): Promise<ManagedKeyInfo[]> {
        throw new Error('listKeys is not implemented for AzureKeyVaultKMS.')
    }

    private mapKeyUsage = (usage: string): JwkUse => {
        switch (usage) {
            case 'sig':
                return JwkUse.sig
            case 'enc':
                return JwkUse.enc
            default:
                throw new Error(`Key usage ${usage} is not supported by AzureKeyVaultKMS`)
        }
    }

    private mapKeyTypeToSignatureAlgorithm = (type: TKeyType): SignatureAlgorithm => {
        switch (type) {
            case 'Secp256r1':
                return SignatureAlgorithm.ECDSA_SHA256
            default:
                throw new Error(`Key type ${type} is not supported by AzureKeyVaultKMS`)
        }
    }

    private mapKeyOperation = (operation: string): KeyOperations => {
        switch (operation) {
            case 'sign':
                return KeyOperations.SIGN
            case 'verify':
                return KeyOperations.VERIFY
            default:
                throw new Error(`Key operation ${operation} is not supported by AzureKeyVaultKMS`)
        }
    }

    private mapKeyOperations = (operations: string[]): KeyOperations[] => {
        return operations.map(operation => this.mapKeyOperation(operation))
    }
}
