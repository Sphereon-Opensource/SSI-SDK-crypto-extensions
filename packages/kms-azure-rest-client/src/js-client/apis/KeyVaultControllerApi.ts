// TODO: better import syntax?
import {BaseAPIRequestFactory, RequiredError, COLLECTION_FORMATS} from './baseapi';
import {Configuration} from '../configuration';
import {RequestContext, HttpMethod, ResponseContext, HttpFile, HttpInfo} from '../http/http';
import {ObjectSerializer} from '../models/ObjectSerializer';
import {ApiException} from './exception';
import {canConsumeForm, isCodeInRange} from '../util';
import {SecurityAuthentication} from '../auth/auth';


import { CreateEcKeyRequest } from '../models/CreateEcKeyRequest';
import { KeyVaultKey } from '../models/KeyVaultKey';
import { SignPayloadDTO } from '../models/SignPayloadDTO';
import { SignPayloadResponse } from '../models/SignPayloadResponse';
import { VerifyPayloadDTO } from '../models/VerifyPayloadDTO';

/**
 * no description
 */
export class KeyVaultControllerApiRequestFactory extends BaseAPIRequestFactory {

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param createEcKeyRequest 
     */
    public async createEcKey(createEcKeyRequest: CreateEcKeyRequest, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'createEcKeyRequest' is not null or undefined
        if (createEcKeyRequest === null || createEcKeyRequest === undefined) {
            throw new RequiredError("KeyVaultControllerApi", "createEcKey", "createEcKeyRequest");
        }


        // Path Params
        const localVarPath = '/api/keys/create-ec-key';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.POST);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        // Body Params
        const contentType = ObjectSerializer.getPreferredMediaType([
            "application/json"
        ]);
        requestContext.setHeaderParam("Content-Type", contentType);
        const serializedBody = ObjectSerializer.stringify(
            ObjectSerializer.serialize(createEcKeyRequest, "CreateEcKeyRequest", ""),
            contentType
        );
        requestContext.setBody(serializedBody);

        let authMethod: SecurityAuthentication | undefined;
        // Apply auth methods
        authMethod = _config.authMethods["apiKeyScheme"]
        if (authMethod?.applySecurityAuthentication) {
            await authMethod?.applySecurityAuthentication(requestContext);
        }
        
        const defaultAuth: SecurityAuthentication | undefined = _options?.authMethods?.default || this.configuration?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param keyName The name of the key to retrieve
     */
    public async getKey(keyName: string, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'keyName' is not null or undefined
        if (keyName === null || keyName === undefined) {
            throw new RequiredError("KeyVaultControllerApi", "getKey", "keyName");
        }


        // Path Params
        const localVarPath = '/api/keys/{keyName}'
            .replace('{' + 'keyName' + '}', encodeURIComponent(String(keyName)));

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.GET);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        let authMethod: SecurityAuthentication | undefined;
        // Apply auth methods
        authMethod = _config.authMethods["apiKeyScheme"]
        if (authMethod?.applySecurityAuthentication) {
            await authMethod?.applySecurityAuthentication(requestContext);
        }
        
        const defaultAuth: SecurityAuthentication | undefined = _options?.authMethods?.default || this.configuration?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param signPayloadDTO 
     */
    public async signPayload(signPayloadDTO: SignPayloadDTO, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'signPayloadDTO' is not null or undefined
        if (signPayloadDTO === null || signPayloadDTO === undefined) {
            throw new RequiredError("KeyVaultControllerApi", "signPayload", "signPayloadDTO");
        }


        // Path Params
        const localVarPath = '/api/keys/sign';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.POST);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        // Body Params
        const contentType = ObjectSerializer.getPreferredMediaType([
            "application/json"
        ]);
        requestContext.setHeaderParam("Content-Type", contentType);
        const serializedBody = ObjectSerializer.stringify(
            ObjectSerializer.serialize(signPayloadDTO, "SignPayloadDTO", ""),
            contentType
        );
        requestContext.setBody(serializedBody);

        let authMethod: SecurityAuthentication | undefined;
        // Apply auth methods
        authMethod = _config.authMethods["apiKeyScheme"]
        if (authMethod?.applySecurityAuthentication) {
            await authMethod?.applySecurityAuthentication(requestContext);
        }
        
        const defaultAuth: SecurityAuthentication | undefined = _options?.authMethods?.default || this.configuration?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param verifyPayloadDTO 
     */
    public async verifyPayload(verifyPayloadDTO: VerifyPayloadDTO, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'verifyPayloadDTO' is not null or undefined
        if (verifyPayloadDTO === null || verifyPayloadDTO === undefined) {
            throw new RequiredError("KeyVaultControllerApi", "verifyPayload", "verifyPayloadDTO");
        }


        // Path Params
        const localVarPath = '/api/keys/verify';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.POST);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        // Body Params
        const contentType = ObjectSerializer.getPreferredMediaType([
            "application/json"
        ]);
        requestContext.setHeaderParam("Content-Type", contentType);
        const serializedBody = ObjectSerializer.stringify(
            ObjectSerializer.serialize(verifyPayloadDTO, "VerifyPayloadDTO", ""),
            contentType
        );
        requestContext.setBody(serializedBody);

        let authMethod: SecurityAuthentication | undefined;
        // Apply auth methods
        authMethod = _config.authMethods["apiKeyScheme"]
        if (authMethod?.applySecurityAuthentication) {
            await authMethod?.applySecurityAuthentication(requestContext);
        }
        
        const defaultAuth: SecurityAuthentication | undefined = _options?.authMethods?.default || this.configuration?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

}

export class KeyVaultControllerApiResponseProcessor {

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to createEcKey
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async createEcKeyWithHttpInfo(response: ResponseContext): Promise<HttpInfo<KeyVaultKey >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("201", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }
        if (isCodeInRange("400", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            throw new ApiException<KeyVaultKey>(response.httpStatusCode, "Invalid input parameters", body, response.headers);
        }
        if (isCodeInRange("500", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            throw new ApiException<KeyVaultKey>(response.httpStatusCode, "Unexpected error during key creation", body, response.headers);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to getKey
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async getKeyWithHttpInfo(response: ResponseContext): Promise<HttpInfo<KeyVaultKey >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("200", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }
        if (isCodeInRange("404", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            throw new ApiException<KeyVaultKey>(response.httpStatusCode, "Key not found", body, response.headers);
        }
        if (isCodeInRange("500", response.httpStatusCode)) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            throw new ApiException<KeyVaultKey>(response.httpStatusCode, "Unexpected error during key retrieval", body, response.headers);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: KeyVaultKey = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "KeyVaultKey", ""
            ) as KeyVaultKey;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to signPayload
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async signPayloadWithHttpInfo(response: ResponseContext): Promise<HttpInfo<SignPayloadResponse >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("200", response.httpStatusCode)) {
            const body: SignPayloadResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "SignPayloadResponse", ""
            ) as SignPayloadResponse;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }
        if (isCodeInRange("400", response.httpStatusCode)) {
            const body: SignPayloadResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "SignPayloadResponse", ""
            ) as SignPayloadResponse;
            throw new ApiException<SignPayloadResponse>(response.httpStatusCode, "Invalid input parameters", body, response.headers);
        }
        if (isCodeInRange("404", response.httpStatusCode)) {
            const body: SignPayloadResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "SignPayloadResponse", ""
            ) as SignPayloadResponse;
            throw new ApiException<SignPayloadResponse>(response.httpStatusCode, "Key not found", body, response.headers);
        }
        if (isCodeInRange("500", response.httpStatusCode)) {
            const body: SignPayloadResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "SignPayloadResponse", ""
            ) as SignPayloadResponse;
            throw new ApiException<SignPayloadResponse>(response.httpStatusCode, "Unexpected error during signing", body, response.headers);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: SignPayloadResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "SignPayloadResponse", ""
            ) as SignPayloadResponse;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to verifyPayload
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async verifyPayloadWithHttpInfo(response: ResponseContext): Promise<HttpInfo<boolean >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("200", response.httpStatusCode)) {
            const body: boolean = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "boolean", ""
            ) as boolean;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }
        if (isCodeInRange("400", response.httpStatusCode)) {
            const body: boolean = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "boolean", ""
            ) as boolean;
            throw new ApiException<boolean>(response.httpStatusCode, "Invalid input parameters", body, response.headers);
        }
        if (isCodeInRange("404", response.httpStatusCode)) {
            const body: boolean = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "boolean", ""
            ) as boolean;
            throw new ApiException<boolean>(response.httpStatusCode, "Key not found", body, response.headers);
        }
        if (isCodeInRange("500", response.httpStatusCode)) {
            const body: boolean = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "boolean", ""
            ) as boolean;
            throw new ApiException<boolean>(response.httpStatusCode, "Unexpected error during verification", body, response.headers);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: boolean = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "boolean", ""
            ) as boolean;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

}
