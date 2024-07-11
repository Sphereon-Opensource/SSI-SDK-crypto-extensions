import { NativeModules } from 'react-native';
import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core';

const { MusapModule } = NativeModules;

export class MusapKeyManagementSystem {
  async listKeys(): Promise<ManagedKeyInfo[]> {
    return new Promise((resolve, reject) => {
      MusapModule.listKeys((error: any, keysJson: string) => {
        if (error) {
          console.error("Failed to list keys:", error);
          reject(error);
        } else {
          const keys: ManagedKeyInfo[] = JSON.parse(keysJson);
          resolve(keys);
        }
      });
    });
  }

  async createKey(args: { type: TKeyType; req: any }): Promise<ManagedKeyInfo> {
    return new Promise((resolve, reject) => {
      MusapModule.generateKey(args.type, args.req, (error: any, result: any) => {
        if (error) {
          console.error("Failed to create key:", error);
          reject(error);
        } else {
          resolve(result);
        }
      });
    });
  }

  async sign(args: {
    keyRef: Pick<IKey, 'kid'>;
    algorithm?: string;
    data: Uint8Array;
  }): Promise<string> {
    return new Promise((resolve, reject) => {
      const req = {
        key: {
          kid: args.keyRef.kid,
          algorithm: args.algorithm,
        },
        data: Array.from(args.data),
      };
      MusapModule.sign(req, (error: any, result: any) => {
        if (error) {
          console.error("Failed to sign data:", error);
          reject(error);
        } else {
          resolve(result);
        }
      });
    });
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    return new Promise((resolve, reject) => {
      MusapModule.importKey({ ...args, keyData: Array.from(args.keyData) }, (error: any, keyJson: string) => {
        if (error) {
          console.error("Failed to import key:", error);
          reject(error);
        } else {
          const key: ManagedKeyInfo = JSON.parse(keyJson);
          resolve(key);
        }
      });
    });
  }
}
