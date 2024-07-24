import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core';
import {
  KeyAlgorithmType,
  KeyGenReq,
  MusapKey,
  MusapModuleType,
  SignatureAlgorithmType,
  SignatureFormat,
  SignatureReq
} from '@sphereon/musap-react-native';
import { SscdType } from '@sphereon/musap-react-native/src/types/musap-types';
import { KeyManagementSystem } from '@veramo/kms-local';
import { AbstractPrivateKeyStore } from '@veramo/key-manager';
import 'react-native-get-random-values'
import { v4 as uuid } from 'uuid';
import { TextDecoder } from 'text-encoding';

export class MusapKeyManagementSystem extends KeyManagementSystem {
  private musapKeyStore: MusapModuleType;

  constructor(keyStore: MusapModuleType) {
    super(keyStore as unknown as AbstractPrivateKeyStore);
    this.musapKeyStore = keyStore;
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    try {
      const keysJson: MusapKey[] = (await this.musapKeyStore.listKeys()) as MusapKey[];
      return keysJson.map((key) => this.asMusapKeyInfo(key));
    } catch (error) {
      console.error('Failed to list keys:', error);
      throw error;
    }
  }

  async createKey(args: { type: TKeyType; sscdType?: SscdType }): Promise<ManagedKeyInfo> {
    const sscdType: SscdType = args.sscdType ? args.sscdType : 'TEE';
    const keyGenReq: KeyGenReq = {
      keyAlgorithm: args.type as KeyAlgorithmType,
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
      const generatedKeyUri = await this.musapKeyStore.generateKey(sscdType, keyGenReq);
      if (generatedKeyUri) {
        console.log('Generated key:', generatedKeyUri);
        const key = await this.musapKeyStore.getKeyByUri(generatedKeyUri)
        return this.asMusapKeyInfo(key);
      } else {
        console.log('Failed to generate key');
        throw new Error('Failed to generate key');
      }
    } catch (error) {
      console.error('An error occurred:', error);
      throw error;
    }
  }

  async deleteKey({ kid }: { kid: string }): Promise<boolean> {
    try {
      await this.musapKeyStore.removeKey(kid);
      return true;
    } catch (error) {
      console.error('Failed to delete key:', error);
      return false;
    }
  }

  async sign(args: { keyRef: Pick<IKey, 'kid'>; algorithm?: string; data: Uint8Array; [x: string]: any }): Promise<string> {
      if (!args.keyRef) {
        throw new Error('key_not_found: No key ref provided');
      }

      let data = ''
      try {
        data = new TextDecoder().decode(args.data as Uint8Array)
      } catch (e) {
        console.log('error on decoding the Uint8Array data', e);
      }

      const key: MusapKey = (this.musapKeyStore.getKeyByUri(args.keyRef.kid)) as MusapKey;
      const signatureReq: SignatureReq = {
        keyUri: key.keyUri,
        data,
        algorithm: args.algorithm as SignatureAlgorithmType,
        displayText: args.displayText,
        transId: args.transId,
        format: args.format as SignatureFormat,
        attributes: args.attributes
      };

      return this.musapKeyStore.sign(signatureReq);
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    throw new Error('Not implemented.');
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
