import {AzureKeyVaultCryptoProvider, com} from '@sphereon/kmp-crypto-kms-azure'
import {IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType} from '@veramo/core'
import {AbstractKeyManagementSystem} from '@veramo/key-manager'
import {KeyMetadata} from './index'
import {calculateJwkThumbprint} from '@sphereon/ssi-sdk-ext.key-utils'
import {JoseCurve, JWK} from "@sphereon/ssi-types";
import AzureKeyVaultClientConfig = com.sphereon.crypto.kms.azure.AzureKeyVaultClientConfig;
import SignatureAlgorithm = com.sphereon.crypto.generic.SignatureAlgorithm;
import KeyOperations = com.sphereon.crypto.generic.KeyOperations;
import JwkUse = com.sphereon.crypto.jose.JwkUse;

export class AzureKeyVaultKeyManagementSystem extends AbstractKeyManagementSystem {
    private id: string
    private client: AzureKeyVaultCryptoProvider

    constructor(private config: AzureKeyVaultClientConfig) {
        super()

        this.id = config.applicationId
        this.client = new AzureKeyVaultCryptoProvider(this.config)
    }

    async createKey(args: { type: TKeyType; meta?: KeyMetadata }): Promise<ManagedKeyInfo> {
        const {type, meta} = args

        const options = new AzureKeyVaultCryptoProvider.GenerateKeyRequest(
            meta?.keyAlias || `key-${crypto.randomUUID()}`,
            meta && 'keyUsage' in meta ? this.mapKeyUsage(meta.keyUsage) : JwkUse.sig,
            meta && 'keyOperations' in meta ? this.mapKeyOperations(meta.keyOperations as string[]) : [KeyOperations.SIGN],
            this.mapKeyTypeToSignatureAlgorithm(type)
        )
        const key = await this.client.generateKeyAsync(options)

        const jwk: JWK = {
            ...key.jose.publicJwk.toPublicKey(),
            kty: key.jose.publicJwk.toPublicKey().kty.name,
            crv: JoseCurve.P_256,
            x: key.jose.publicJwk.toPublicKey().x || undefined,
            y: key.jose.publicJwk.toPublicKey().y || undefined,
            kid: key.jose.publicJwk.toPublicKey().kid || undefined
        }

        const managedKeyInfo: ManagedKeyInfo = {
            kid: key.kmsKeyRef,
            kms: this.id,
            type,
            meta: {
                alias: key.kid,
                algorithms: [key.jose.publicJwk.alg?.name ?? 'ES256'],
                jwkThumbprint: calculateJwkThumbprint(
                    {
                        jwk,
                        digestAlgorithm: 'sha256'
                    }
                )
            },
            publicKeyHex: Buffer.from(key.jose.toString(), 'utf8').toString('base64'),
        }

        return managedKeyInfo
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
        const signature =  await this.client.createRawSignatureAsync({
            keyInfo: key,
            // @ts-ignore
            input: args.data
        })

        return Buffer.from(signature).toString('hex');
    }

    async verify(args: {
        keyRef: Pick<IKey, 'kid'>;
        data: Uint8Array;
        signature: string;
        [x: string]: any
    }): Promise<Boolean> {
        if (!args.keyRef) {
            throw new Error('key_not_found: No key ref provided')
        }

        try {
            const key = await this.client.fetchKeyAsync(args.keyRef.kid)
            return await this.client.isValidRawSignatureAsync({
                keyInfo: key,
                // @ts-ignore
                signature: Buffer.from(args.signature, 'hex'),
                // @ts-ignore
                input: args.data
            })
        } catch (e) {
            console.error(e)
            return false
        }
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
