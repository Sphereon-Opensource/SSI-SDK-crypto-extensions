import { ResponseContext, RequestContext, HttpFile, HttpInfo } from '../http/http';
import { Configuration} from '../configuration'
import { Observable, of, from } from '../rxjsStub';
import {mergeMap, map} from  '../rxjsStub';
import { BinaryData } from '../models/BinaryData';
import { CreateEcKeyRequest } from '../models/CreateEcKeyRequest';
import { JsonWebKey } from '../models/JsonWebKey';
import { KeyProperties } from '../models/KeyProperties';
import { KeyReleasePolicy } from '../models/KeyReleasePolicy';
import { KeyVaultKey } from '../models/KeyVaultKey';
import { SignPayloadDTO } from '../models/SignPayloadDTO';
import { SignPayloadResponse } from '../models/SignPayloadResponse';
import { VerifyPayloadDTO } from '../models/VerifyPayloadDTO';

import { KeyVaultControllerApiRequestFactory, KeyVaultControllerApiResponseProcessor} from "../apis/KeyVaultControllerApi";
export class ObservableKeyVaultControllerApi {
    private requestFactory: KeyVaultControllerApiRequestFactory;
    private responseProcessor: KeyVaultControllerApiResponseProcessor;
    private configuration: Configuration;

    public constructor(
        configuration: Configuration,
        requestFactory?: KeyVaultControllerApiRequestFactory,
        responseProcessor?: KeyVaultControllerApiResponseProcessor
    ) {
        this.configuration = configuration;
        this.requestFactory = requestFactory || new KeyVaultControllerApiRequestFactory(configuration);
        this.responseProcessor = responseProcessor || new KeyVaultControllerApiResponseProcessor();
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param createEcKeyRequest
     */
    public createEcKeyWithHttpInfo(createEcKeyRequest: CreateEcKeyRequest, _options?: Configuration): Observable<HttpInfo<KeyVaultKey>> {
        const requestContextPromise = this.requestFactory.createEcKey(createEcKeyRequest, _options);

        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of this.configuration.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => this.configuration.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of this.configuration.middleware) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.createEcKeyWithHttpInfo(rsp)));
            }));
    }

    /**
     * Creates an EC key in Azure Key Vault with the specified curve and key operations
     * Create an EC Key
     * @param createEcKeyRequest
     */
    public createEcKey(createEcKeyRequest: CreateEcKeyRequest, _options?: Configuration): Observable<KeyVaultKey> {
        return this.createEcKeyWithHttpInfo(createEcKeyRequest, _options).pipe(map((apiResponse: HttpInfo<KeyVaultKey>) => apiResponse.data));
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param keyName The name of the key to retrieve
     */
    public getKeyWithHttpInfo(keyName: string, _options?: Configuration): Observable<HttpInfo<KeyVaultKey>> {
        const requestContextPromise = this.requestFactory.getKey(keyName, _options);

        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of this.configuration.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => this.configuration.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of this.configuration.middleware) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.getKeyWithHttpInfo(rsp)));
            }));
    }

    /**
     * Retrieves the specified key from Azure Key Vault
     * Get a Key
     * @param keyName The name of the key to retrieve
     */
    public getKey(keyName: string, _options?: Configuration): Observable<KeyVaultKey> {
        return this.getKeyWithHttpInfo(keyName, _options).pipe(map((apiResponse: HttpInfo<KeyVaultKey>) => apiResponse.data));
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param signPayloadDTO
     */
    public signPayloadWithHttpInfo(signPayloadDTO: SignPayloadDTO, _options?: Configuration): Observable<HttpInfo<SignPayloadResponse>> {
        const requestContextPromise = this.requestFactory.signPayload(signPayloadDTO, _options);

        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of this.configuration.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => this.configuration.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of this.configuration.middleware) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.signPayloadWithHttpInfo(rsp)));
            }));
    }

    /**
     * Signs the specified payload using the specified key in Azure Key Vault
     * Sign a payload
     * @param signPayloadDTO
     */
    public signPayload(signPayloadDTO: SignPayloadDTO, _options?: Configuration): Observable<SignPayloadResponse> {
        return this.signPayloadWithHttpInfo(signPayloadDTO, _options).pipe(map((apiResponse: HttpInfo<SignPayloadResponse>) => apiResponse.data));
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param verifyPayloadDTO
     */
    public verifyPayloadWithHttpInfo(verifyPayloadDTO: VerifyPayloadDTO, _options?: Configuration): Observable<HttpInfo<boolean>> {
        const requestContextPromise = this.requestFactory.verifyPayload(verifyPayloadDTO, _options);

        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of this.configuration.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => this.configuration.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of this.configuration.middleware) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.verifyPayloadWithHttpInfo(rsp)));
            }));
    }

    /**
     * Verifies the specified payload using the specified key in Azure Key Vault
     * Verify a payload
     * @param verifyPayloadDTO
     */
    public verifyPayload(verifyPayloadDTO: VerifyPayloadDTO, _options?: Configuration): Observable<boolean> {
        return this.verifyPayloadWithHttpInfo(verifyPayloadDTO, _options).pipe(map((apiResponse: HttpInfo<boolean>) => apiResponse.data));
    }

}
