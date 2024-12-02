import { ResponseContext, RequestContext, HttpFile, HttpInfo } from '../http/http';
import { Configuration} from '../configuration'

import { BinaryData } from '../models/BinaryData';
import { CreateEcKeyRequest } from '../models/CreateEcKeyRequest';
import { JsonWebKey } from '../models/JsonWebKey';
import { KeyProperties } from '../models/KeyProperties';
import { KeyReleasePolicy } from '../models/KeyReleasePolicy';
import { KeyVaultKey } from '../models/KeyVaultKey';
import { SignPayloadDTO } from '../models/SignPayloadDTO';
import { SignPayloadResponse } from '../models/SignPayloadResponse';
import { VerifyPayloadDTO } from '../models/VerifyPayloadDTO';

import { ObservableKeyVaultControllerApi } from "./ObservableAPI";
import { KeyVaultControllerApiRequestFactory, KeyVaultControllerApiResponseProcessor} from "../apis/KeyVaultControllerApi";

export interface KeyVaultControllerApiCreateEcKeyRequest {
    /**
     * 
     * @type CreateEcKeyRequest
     * @memberof KeyVaultControllerApicreateEcKey
     */
    createEcKeyRequest: CreateEcKeyRequest
}

export interface KeyVaultControllerApiGetKeyRequest {
    /**
     * The name of the key to retrieve
     * Defaults to: undefined
     * @type string
     * @memberof KeyVaultControllerApigetKey
     */
    keyName: string
}

export interface KeyVaultControllerApiSignPayloadRequest {
    /**
     * 
     * @type SignPayloadDTO
     * @memberof KeyVaultControllerApisignPayload
     */
    signPayloadDTO: SignPayloadDTO
}

export interface KeyVaultControllerApiVerifyPayloadRequest {
    /**
     * 
     * @type VerifyPayloadDTO
     * @memberof KeyVaultControllerApiverifyPayload
     */
    verifyPayloadDTO: VerifyPayloadDTO
}

export class ObjectKeyVaultControllerApi {
    private api: ObservableKeyVaultControllerApi

    public constructor(configuration: Configuration, requestFactory?: KeyVaultControllerApiRequestFactory, responseProcessor?: KeyVaultControllerApiResponseProcessor) {
        this.api = new ObservableKeyVaultControllerApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param param the request object
     */
    public createEcKeyWithHttpInfo(param: KeyVaultControllerApiCreateEcKeyRequest, options?: Configuration): Promise<HttpInfo<KeyVaultKey>> {
        return this.api.createEcKeyWithHttpInfo(param.createEcKeyRequest,  options).toPromise();
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param param the request object
     */
    public createEcKey(param: KeyVaultControllerApiCreateEcKeyRequest, options?: Configuration): Promise<KeyVaultKey> {
        return this.api.createEcKey(param.createEcKeyRequest,  options).toPromise();
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param param the request object
     */
    public getKeyWithHttpInfo(param: KeyVaultControllerApiGetKeyRequest, options?: Configuration): Promise<HttpInfo<KeyVaultKey>> {
        return this.api.getKeyWithHttpInfo(param.keyName,  options).toPromise();
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param param the request object
     */
    public getKey(param: KeyVaultControllerApiGetKeyRequest, options?: Configuration): Promise<KeyVaultKey> {
        return this.api.getKey(param.keyName,  options).toPromise();
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param param the request object
     */
    public signPayloadWithHttpInfo(param: KeyVaultControllerApiSignPayloadRequest, options?: Configuration): Promise<HttpInfo<SignPayloadResponse>> {
        return this.api.signPayloadWithHttpInfo(param.signPayloadDTO,  options).toPromise();
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param param the request object
     */
    public signPayload(param: KeyVaultControllerApiSignPayloadRequest, options?: Configuration): Promise<SignPayloadResponse> {
        return this.api.signPayload(param.signPayloadDTO,  options).toPromise();
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param param the request object
     */
    public verifyPayloadWithHttpInfo(param: KeyVaultControllerApiVerifyPayloadRequest, options?: Configuration): Promise<HttpInfo<boolean>> {
        return this.api.verifyPayloadWithHttpInfo(param.verifyPayloadDTO,  options).toPromise();
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param param the request object
     */
    public verifyPayload(param: KeyVaultControllerApiVerifyPayloadRequest, options?: Configuration): Promise<boolean> {
        return this.api.verifyPayload(param.verifyPayloadDTO,  options).toPromise();
    }

}
