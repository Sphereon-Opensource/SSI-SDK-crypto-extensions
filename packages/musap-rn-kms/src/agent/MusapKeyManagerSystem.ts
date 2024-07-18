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
import { v4 as uuid } from 'uuid';

// Utility function to convert Uint8Array to string
function uint8ArrayToString(data: Uint8Array): string {
  return String.fromCharCode.apply(null, Array.from(data));
}

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
      const generatedKey = await this.generateKeyWrapper(sscdType, keyGenReq);
      if (generatedKey) {
        console.log('Generated key:', generatedKey);
        return this.asMusapKeyInfo(generatedKey);
      } else {
        console.log('Failed to generate key');
        throw new Error('Failed to generate key');
      }
    } catch (error) {
      console.error('An error occurred:', error);
      throw error;
    }
  }

  async generateKeyWrapper(type: SscdType, keyGenRequest: KeyGenReq): Promise<MusapKey | undefined> {
    return new Promise((resolve) => {
      this.musapKeyStore.generateKey(type, keyGenRequest, (error: any | undefined, keyUri: string | undefined) => {
        if (this.musapKeyStore.listEnabledSscds()[0].sscdInfo.sscdName === 'SE' && error) {
          console.log(error);
          resolve(undefined);
        } else if (error) {
          console.log(error);
          resolve(undefined);
        } else if (keyUri) {
          console.log(`Key successfully generated: ${keyUri}`);
          const key = this.musapKeyStore.getKeyByUri(keyUri) as MusapKey;
          resolve(key);
        } else {
          resolve(undefined);
        }
      });
    });
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
    return new Promise(async (resolve, reject) => {
      if (!args.keyRef) {
        reject(new Error('key_not_found: No key ref provided'));
        return;
      }

      let data = '';
      try {
        data = uint8ArrayToString(args.data);
      } catch (e) {
        console.log('error on converting the Uint8Array data', e);
      }
      const key: MusapKey = (await this.musapKeyStore.getKeyByUri(args.keyRef.kid)) as MusapKey;
      const signatureReq: SignatureReq = {
        key,
        data,
        algorithm: args.algorithm as SignatureAlgorithmType,
        displayText: args.displayText,
        transId: args.transId,
        format: args.format as SignatureFormat,
        attributes: args.attributes
      };

      this.musapKeyStore.sign(signatureReq, (error: string | undefined, signed: string | undefined) => {
        if (error) {
          console.error('Failed to sign data:', error);
          reject(error);
        } else if (signed) {
          resolve(signed);
        } else {
          reject('Unknown error during signing');
        }
      });
    });
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
