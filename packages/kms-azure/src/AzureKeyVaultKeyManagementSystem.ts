import {AzureKeyVaultCryptoProvider, com} from '@sphereon/kmp-crypto-kms-azure'
import {IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType} from '@veramo/core'
import {AbstractKeyManagementSystem} from '@veramo/key-manager'
import {Loggers} from '@sphereon/ssi-types'
import {KeyMetadata} from './index'
import AzureKeyvaultClientConfig = com.sphereon.crypto.kms.azure.AzureKeyvaultClientConfig;
import SignatureAlgorithm = com.sphereon.crypto.generic.SignatureAlgorithm;
import KeyOperations = com.sphereon.crypto.generic.KeyOperations;
import JwkUse = com.sphereon.crypto.jose.JwkUse;
import ManagedKeyPair = com.sphereon.crypto.generic.ManagedKeyPair;
import JwaCurve = com.sphereon.crypto.jose.JwaCurve;
import {calculateJwkThumbprintForKey} from "@sphereon/ssi-sdk-ext.key-utils";

export const logger = Loggers.DEFAULT.get('sphereon:azure-key-vault-ssi-sdk')

export class AzureKeyVaultKeyManagementSystem extends AbstractKeyManagementSystem {
    private client: AzureKeyVaultCryptoProvider

    constructor(private config : AzureKeyvaultClientConfig) {
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

        return this.asManagedKeyInfo(await this.client.generateKeyAsync(options))
    }

    async sign(args: {
        keyRef: Pick<IKey, 'kid'>;
        data: Uint8Array;
        [x: string]: any
    }): Promise<string> {
        if (!args.keyRef) {
            throw new Error('key_not_found: No key ref provided')
        }

        const key = await this.client.getAzureKeyVaultJwk(args.keyRef.kid)

        return (await this.client.createRawSignatureAsync({key, data: args.data, algorithm: args.algorithm || 'SHA256'})).toString()
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

    private asManagedKeyInfo(args: ManagedKeyPair): ManagedKeyInfo {
        const { jose }: ManagedKeyPair = args
        const keyType = this.mapAlgorithmTypeToKeyType(jose.publicJwk.crv!!)

        const keyInfo: Partial<ManagedKeyInfo> = {
            kid: jose.publicJwk.kid!!,
            type: keyType,
            publicKeyHex: jose.publicJwk.toString(),
            meta: {
                keyUsage: jose.publicJwk.use,
                keyOperations: jose.publicJwk.key_ops
            }
        }

        const jwkThumbprint = calculateJwkThumbprintForKey({ key: keyInfo as ManagedKeyInfo })
        keyInfo.meta = { ...keyInfo.meta, jwkThumbprint }
        return keyInfo as ManagedKeyInfo
    }

    private mapAlgorithmTypeToKeyType = (type: JwaCurve): TKeyType => {
        switch (type) {
            case JwaCurve.P_256:
                return 'Secp256r1'
            default:
                throw new Error(`Key type ${type} is not supported.`)
        }
    }
}
