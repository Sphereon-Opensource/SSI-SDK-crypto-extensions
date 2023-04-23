import { TKeyType } from '@veramo/core'
export { SphereonKeyManagementSystem } from './SphereonKeyManagementSystem'
export type ManagedKeyInfoArgs = { alias?: string; type: TKeyType; privateKeyHex: string; publicKeyHex?: string }
export enum KeyType {
  Bls12381G2 = 'Bls12381G2',
}
