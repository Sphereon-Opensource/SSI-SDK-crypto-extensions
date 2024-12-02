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
import { ObservableKeyVaultControllerApi } from './ObservableAPI';

import { KeyVaultControllerApiRequestFactory, KeyVaultControllerApiResponseProcessor} from "../apis/KeyVaultControllerApi";
export class PromiseKeyVaultControllerApi {
    private api: ObservableKeyVaultControllerApi

    public constructor(
        configuration: Configuration,
        requestFactory?: KeyVaultControllerApiRequestFactory,
        responseProcessor?: KeyVaultControllerApiResponseProcessor
    ) {
        this.api = new ObservableKeyVaultControllerApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param createEcKeyRequest
     */
    public createEcKeyWithHttpInfo(createEcKeyRequest: CreateEcKeyRequest, _options?: Configuration): Promise<HttpInfo<KeyVaultKey>> {
        const result = this.api.createEcKeyWithHttpInfo(createEcKeyRequest, _options);
        return result.toPromise();
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param createEcKeyRequest
     */
    public createEcKey(createEcKeyRequest: CreateEcKeyRequest, _options?: Configuration): Promise<KeyVaultKey> {
        const result = this.api.createEcKey(createEcKeyRequest, _options);
        return result.toPromise();
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param keyName The name of the key to retrieve
     */
    public getKeyWithHttpInfo(keyName: string, _options?: Configuration): Promise<HttpInfo<KeyVaultKey>> {
        const result = this.api.getKeyWithHttpInfo(keyName, _options);
        return result.toPromise();
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param keyName The name of the key to retrieve
     */
    public getKey(keyName: string, _options?: Configuration): Promise<KeyVaultKey> {
        const result = this.api.getKey(keyName, _options);
        return result.toPromise();
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param signPayloadDTO
     */
    public signPayloadWithHttpInfo(signPayloadDTO: SignPayloadDTO, _options?: Configuration): Promise<HttpInfo<SignPayloadResponse>> {
        const result = this.api.signPayloadWithHttpInfo(signPayloadDTO, _options);
        return result.toPromise();
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param signPayloadDTO
     */
    public signPayload(signPayloadDTO: SignPayloadDTO, _options?: Configuration): Promise<SignPayloadResponse> {
        const result = this.api.signPayload(signPayloadDTO, _options);
        return result.toPromise();
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param verifyPayloadDTO
     */
    public verifyPayloadWithHttpInfo(verifyPayloadDTO: VerifyPayloadDTO, _options?: Configuration): Promise<HttpInfo<boolean>> {
        const result = this.api.verifyPayloadWithHttpInfo(verifyPayloadDTO, _options);
        return result.toPromise();
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param verifyPayloadDTO
     */
    public verifyPayload(verifyPayloadDTO: VerifyPayloadDTO, _options?: Configuration): Promise<boolean> {
        const result = this.api.verifyPayload(verifyPayloadDTO, _options);
        return result.toPromise();
    }


}



