export * from '../models/BinaryData';
export * from '../models/CreateEcKeyRequest';
export * from '../models/JsonWebKey';
export * from '../models/KeyProperties';
export * from '../models/KeyReleasePolicy';
export * from '../models/KeyVaultKey';
export * from '../models/SignPayloadDTO';
export * from '../models/SignPayloadResponse';
export * from '../models/VerifyPayloadDTO';
export declare class ObjectSerializer {
    static findCorrectType(data: any, expectedType: string): any;
    static serialize(data: any, type: string, format: string): any;
    static deserialize(data: any, type: string, format: string): any;
    static normalizeMediaType(mediaType: string | undefined): string | undefined;
    static getPreferredMediaType(mediaTypes: Array<string>): string;
    static stringify(data: any, mediaType: string): string;
    static parse(rawData: string, mediaType: string | undefined): any;
}