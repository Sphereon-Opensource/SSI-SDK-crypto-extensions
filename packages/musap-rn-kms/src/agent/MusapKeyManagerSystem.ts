import { KeyManager as VeramoKeyManager, AbstractKeyManagementSystem, AbstractKeyStore } from '@veramo/key-manager';
import { IKey, ManagedKeyInfo, TKeyType } from '@veramo/core';
import { MusapKms } from './MusapKms'; // Import the newly created MusapKms class

export class SphereonKeyManager extends VeramoKeyManager {
  private localStore: AbstractKeyStore;
  private readonly availableKMSes: Record<string, AbstractKeyManagementSystem>;
  private musapKms: MusapKms;

  constructor(options: { store: AbstractKeyStore; kms: Record<string, AbstractKeyManagementSystem> }) {
    super({ store: options.store, kms: options.kms });
    this.localStore = options.store;
    this.availableKMSes = options.kms;
    this.musapKms = new MusapKms();
    const methods = this.methods;
    methods.keyManagerVerify = this.keyManagerVerify.bind(this);
    methods.keyManagerListKeys = this.keyManagerListKeys.bind(this);
  }

  private getAvailableKms(name: string): AbstractKeyManagementSystem {
    const kms = this.availableKMSes[name];
    if (!kms) {
      throw Error(`invalid_argument: This agent has no registered KeyManagementSystem with name='${name}'`);
    }
    return kms;
  }

  async keyManagerSign(args: { keyRef: string; data: string }): Promise<string> {
    const keyInfo: IKey = (await this.localStore.get({ kid: args.keyRef })) as IKey;
    const kms = this.getAvailableKms(keyInfo.kms);
    if (keyInfo.type === KeyType.Bls12381G2) {
      return await kms.sign({ keyRef: keyInfo, data: Uint8Array.from(Buffer.from(args.data)) });
    }
    return await super.keyManagerSign(args);
  }

  async keyManagerListKeys(): Promise<ManagedKeyInfo[]> {
    return await this.musapKms.listKeys();
  }
}
