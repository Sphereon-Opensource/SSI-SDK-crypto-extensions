import { NativeModules } from 'react-native';
import { IKey, ManagedKeyInfo, MinimalImportableKey, TKeyType } from '@veramo/core';

const { MusapModule } = NativeModules;

export class MusapKeyManagementSystem {
  async listKeys(): Promise<ManagedKeyInfo[]> {
    try {
      const keysJson = await MusapModule.listKeys();
      const keys: ManagedKeyInfo[] = JSON.parse(keysJson);
      return keys;
    } catch (error) {
      console.error("Failed to list keys:", error);
      throw new Error(error);
    }
  }

  async createKey(args: { type: TKeyType; meta?: any }): Promise<ManagedKeyInfo> {
    try {
      const keyJson = await MusapModule.createKey({ sscdType: args.type, meta: args.meta });
      const key: ManagedKeyInfo = JSON.parse(keyJson);
      return key;
    } catch (error) {
      console.error("Failed to create key:", error);
      throw new Error(error);
    }
  }

  async deleteKey(kid: string): Promise<boolean> {
    try {
      const result = await MusapModule.deleteKey({ kid });
      return result;
    } catch (error) {
      console.error("Failed to delete key:", error);
      throw new Error(error);
    }
  }

  async sign(args: {
    keyRef: Pick<IKey, 'kid'>;
    algorithm?: string;
    data: Uint8Array;
    [x: string]: any;
  }): Promise<string> {
    try {
      const result = await MusapModule.sign({
        keyRef: args.keyRef.kid,
        algorithm: args.algorithm,
        data: Array.from(args.data)
      });
      return result;
    } catch (error) {
      console.error("Failed to sign data:", error);
      throw new Error(error);
    }
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'> & { privateKeyPEM?: string }): Promise<ManagedKeyInfo> {
    try {
      const keyJson = await MusapModule.importKey({ ...args, keyData: Array.from(args.keyData) });
      const key: ManagedKeyInfo = JSON.parse(keyJson);
      return key;
    } catch (error) {
      console.error("Failed to import key:", error);
      throw new Error(error);
    }
  }
}
