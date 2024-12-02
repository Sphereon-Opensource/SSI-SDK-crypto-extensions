# .KeyVaultControllerApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createEcKey**](KeyVaultControllerApi.md#createEcKey) | **POST** /api/keys/create-ec-key | Create an EC Key
[**getKey**](KeyVaultControllerApi.md#getKey) | **GET** /api/keys/{keyName} | Get a Key
[**signPayload**](KeyVaultControllerApi.md#signPayload) | **POST** /api/keys/sign | Sign a payload
[**verifyPayload**](KeyVaultControllerApi.md#verifyPayload) | **POST** /api/keys/verify | Verify a payload


# **createEcKey**
> KeyVaultKey createEcKey(createEcKeyRequest)

Creates an EC key in Azure Key Vault with the specified curve and key operations

### Example


```typescript
import { createConfiguration, KeyVaultControllerApi } from '';
import type { KeyVaultControllerApiCreateEcKeyRequest } from '';

const configuration = createConfiguration();
const apiInstance = new KeyVaultControllerApi(configuration);

const request: KeyVaultControllerApiCreateEcKeyRequest = {
  
  createEcKeyRequest: {
    keyName: "keyName_example",
    curveName: "curveName_example",
    operations: [
      "operations_example",
    ],
  },
};

const data = await apiInstance.createEcKey(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **createEcKeyRequest** | **CreateEcKeyRequest**|  |


### Return type

**KeyVaultKey**

### Authorization

[apiKeyScheme](README.md#apiKeyScheme)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | EC key successfully created |  -  |
**400** | Invalid input parameters |  -  |
**500** | Unexpected error during key creation |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **getKey**
> KeyVaultKey getKey()

Retrieves the specified key from Azure Key Vault

### Example


```typescript
import { createConfiguration, KeyVaultControllerApi } from '';
import type { KeyVaultControllerApiGetKeyRequest } from '';

const configuration = createConfiguration();
const apiInstance = new KeyVaultControllerApi(configuration);

const request: KeyVaultControllerApiGetKeyRequest = {
    // The name of the key to retrieve
  keyName: "keyName_example",
};

const data = await apiInstance.getKey(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyName** | [**string**] | The name of the key to retrieve | defaults to undefined


### Return type

**KeyVaultKey**

### Authorization

[apiKeyScheme](README.md#apiKeyScheme)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Key successfully retrieved |  -  |
**404** | Key not found |  -  |
**500** | Unexpected error during key retrieval |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **signPayload**
> SignPayloadResponse signPayload(signPayloadDTO)

Signs the specified payload using the specified key in Azure Key Vault

### Example


```typescript
import { createConfiguration, KeyVaultControllerApi } from '';
import type { KeyVaultControllerApiSignPayloadRequest } from '';

const configuration = createConfiguration();
const apiInstance = new KeyVaultControllerApi(configuration);

const request: KeyVaultControllerApiSignPayloadRequest = {
  
  signPayloadDTO: {
    keyName: "keyName_example",
    payload: "payload_example",
  },
};

const data = await apiInstance.signPayload(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **signPayloadDTO** | **SignPayloadDTO**|  |


### Return type

**SignPayloadResponse**

### Authorization

[apiKeyScheme](README.md#apiKeyScheme)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Payload successfully signed |  -  |
**400** | Invalid input parameters |  -  |
**404** | Key not found |  -  |
**500** | Unexpected error during signing |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **verifyPayload**
> boolean verifyPayload(verifyPayloadDTO)

Verifies the specified payload using the specified key in Azure Key Vault

### Example


```typescript
import { createConfiguration, KeyVaultControllerApi } from '';
import type { KeyVaultControllerApiVerifyPayloadRequest } from '';

const configuration = createConfiguration();
const apiInstance = new KeyVaultControllerApi(configuration);

const request: KeyVaultControllerApiVerifyPayloadRequest = {
  
  verifyPayloadDTO: {
    keyName: "keyName_example",
    payload: "payload_example",
    signature: "signature_example",
  },
};

const data = await apiInstance.verifyPayload(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **verifyPayloadDTO** | **VerifyPayloadDTO**|  |


### Return type

**boolean**

### Authorization

[apiKeyScheme](README.md#apiKeyScheme)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Verification performed successfully. |  -  |
**400** | Invalid input parameters |  -  |
**404** | Key not found |  -  |
**500** | Unexpected error during verification |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)


