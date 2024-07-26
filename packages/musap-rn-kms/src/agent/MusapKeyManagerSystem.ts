import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core';
import {
  KeyAlgorithmType,
  KeyGenReq,
  MusapKey,
  MusapModuleType, signatureAlgorithmFromKeyAlgorithm,
  SignatureAlgorithmType,
  SignatureFormat,
  SignatureReq,
} from '@sphereon/musap-react-native'
import { SscdType } from '@sphereon/musap-react-native/src/types/musap-types';
import { KeyManagementSystem } from '@veramo/kms-local';
import { AbstractPrivateKeyStore } from '@veramo/key-manager';
import 'react-native-get-random-values'
import { v4 as uuid } from 'uuid';
import { TextDecoder } from 'text-encoding';
import Debug from 'debug'

const debug = Debug('sphereon:musap-rn-kms')

export class MusapKeyManagementSystem extends KeyManagementSystem {
  private musapKeyStore: MusapModuleType;
  private sscdType: SscdType;

  constructor(keyStore: MusapModuleType, sscdType?: SscdType) {
    super(keyStore as unknown as AbstractPrivateKeyStore);
    this.musapKeyStore = keyStore;
    this.sscdType = sscdType ? sscdType : 'TEE';
    this.musapKeyStore.enableSscd(this.sscdType)
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    try {
      const keysJson: MusapKey[] = (await this.musapKeyStore.listKeys()) as MusapKey[];
      return keysJson.map((key) => this.asMusapKeyInfo(key));
    } catch (error) {
      throw error;
    }
  }

  async createKey(args: { type: TKeyType; sscdType?: SscdType }): Promise<ManagedKeyInfo> {
    const keyAlgorithm = this.mapKeyTypeToAlgorithmType(args.type);

    const keyGenReq: KeyGenReq = {
      keyAlgorithm: keyAlgorithm,
      did: '',
      keyUsage: 'sign',
      keyAlias: uuid(),
      attributes: [
        { name: 'purpose', value: 'encrypt' },
        { name: 'purpose', value: 'decrypt' }
      ],
      role: 'administrator'
    };

    try {
      const generatedKeyUri = await this.musapKeyStore.generateKey(this.sscdType, keyGenReq);
      if (generatedKeyUri) {
        debug('Generated key:', generatedKeyUri);
        const key = await this.musapKeyStore.getKeyByUri(generatedKeyUri);
        return this.asMusapKeyInfo(key);
      } else {
        throw new Error('Failed to generate key');
      }
    } catch (error) {
      console.error('An error occurred:', error);
      throw error;
    }
  }

  mapKeyTypeToAlgorithmType = (type: TKeyType): KeyAlgorithmType => {
    switch (type) {
      case 'Secp256k1':
        return 'ECCP256K1';
      case 'Secp256r1':
        return 'ECCP256R1';
      case 'RSA':
        return 'RSA2K';
      default:
        throw new Error(`Key type ${type} is not supported by MUSAP`);
    }
  }

  async deleteKey({ kid }: { kid: string }): Promise<boolean> {
    try {
      await this.musapKeyStore.removeKey(kid);
      return true;
    } catch (error) {
      console.warn('Failed to delete key:', error);
      return false;
    }
  }

  async sign(args: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array; [x: string]: any }): Promise<string> {
      if (!args.keyRef) {
        throw new Error('key_not_found: No key ref provided');
      }

      const data = new TextDecoder().decode(args.data as Uint8Array)

      const key: MusapKey = (this.musapKeyStore.getKeyById(args.keyRef.kid)) as MusapKey;
      const signatureReq: SignatureReq = {
        keyUri: key.keyUri,
        data,
        algorithm: args.algorithm as SignatureAlgorithmType ?? signatureAlgorithmFromKeyAlgorithm(key.algorithm),
        displayText: args.displayText,
        transId: args.transId,
        format: args.format as SignatureFormat ?? 'RAW',
        attributes: args.attributes
      }
      return this.musapKeyStore.sign(signatureReq)
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('Not supported; MUSAP is a hardware key-store which cannot import keys.');
  }

  private asMusapKeyInfo(args: MusapKey): ManagedKeyInfo & { keyUri?: string } {
    return {
      kid: args.keyId,
      kms: args.sscdId,
      type: args.keyType as unknown as TKeyType,
      publicKeyHex: args.publicKey.toString(),
      keyUri: args.keyUri
    };
  }
}
