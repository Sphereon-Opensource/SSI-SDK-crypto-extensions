import {
  AddVerificationMethodParams,
  AddVerificationMethodRelationshipParams,
  ApiOpts,
  GetDidDocumentParams,
  GetDidDocumentsParams,
  GetDidDocumentsResponse,
  InsertDidDocumentParams,
  jsonrpc,
  Response,
  RPCParams,
  SendSignedTransactionParams,
  UpdateBaseDocumentParams
} from '../types'
import {DIDDocument} from 'did-resolver'
import {getDidRegistryRPCUrl} from "../functions";

/**
 * @constant {string} jsonrpc
 */


/**
 * Call to build an unsigned transaction to insert a new DID document. Requires an access token with "didr_invite" or
 * "didr_write" scope.
 * @param {{ id: InsertDidDocumentParams[], id: number, token: string, apiOpts?: ApiOpts }} args
 */
export const insertDidDocument = async (args: { params: InsertDidDocumentParams[]; id: number;  token: string; apiOpts?: ApiOpts }): Promise<Response> => {
  const { params, id, token, apiOpts } = args
  const options = buildFetchOptions({ token, params, id, method: 'insertDidDocument' })
  return await (await fetch(getDidRegistryRPCUrl({...apiOpts}), options)).json()
}

/**
 * Call to build an unsigned transaction to update the base document of an existing DID. Requires an access token with
 * "didr_write" scope.
 * @param {{ params: UpdateBaseDocumentParams[], id: number, token: string, apiOpts?: ApiOpts }} args
 */
export const updateBaseDocument = async (args: { params: UpdateBaseDocumentParams[]; id: number; token: string; apiOpts?: ApiOpts }): Promise<Response> => {
  const { params, id, token, apiOpts } = args
  const options = buildFetchOptions({ token, params, id, method: 'updateBaseDocument' })
  return await (await fetch(getDidRegistryRPCUrl({...apiOpts}), options)).json()
}

/**
 * Call to build an unsigned transaction to add a verification method. Requires an access token with "didr_write" scope.
 * @param {{ params: AddVerificationMethodParams[], id: number, token: string, apiOpts?: ApiOpts }} args
 */
export const addVerificationMethod = async (args: { params: AddVerificationMethodParams[]; id: number; token: string; apiOpts?: ApiOpts }): Promise<Response> => {
  const { params, id, token, apiOpts } = args
  const options = buildFetchOptions({ token, params, id, method: 'addVerificationMethod' })
  return await (await fetch(getDidRegistryRPCUrl({...apiOpts}), options)).json()
}

/**
 * Call to build an unsigned transaction to add a verification relationship. Requires an access token with "didr_write" scope.
 * @param {{ params: AddVerificationMethodRelationshipParams[], id: number, token: string, apiOpts?: ApiOpts }} args
 */
export const addVerificationMethodRelationship = async (args: {
  params: AddVerificationMethodRelationshipParams[]
  id: number
  token: string
  apiOpts?: ApiOpts
}): Promise<Response> => {
  const { params, id, token, apiOpts } = args
  const options = buildFetchOptions({ token, params, id, method: 'addVerificationMethodRelationship' })
  return await (await fetch(getDidRegistryRPCUrl({...apiOpts}), options)).json()
}

/**
 * Call to send a signed transaction to the blockchain. Requires an access token with "didr_invite" or "didr_write" scope.
 * @param {{ params: SendSignedTransactionParams[], id: number, token: string, apiOpts?: ApiOpts}} args
 */
export const sendSignedTransaction = async (args: { params: SendSignedTransactionParams[]; id: number; token: string; apiOpts?: ApiOpts }): Promise<Response> => {
  const { params, id, token, apiOpts } = args
  const options = buildFetchOptions({ token, params, id, method: 'sendSignedTransaction' });
  return await (await fetch(getDidRegistryRPCUrl({...apiOpts}), options)).json()
}

const buildFetchOptions = (args: { params: RPCParams[], id: number, token: string, method: string }) => {
  const { params, id, token, method } = args
  return {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + token,
    },
    body: JSON.stringify({
      jsonrpc,
      method,
      params,
      id,
    }),
  }
}

/**
 * Gets the DID document corresponding to the DID.
 * @param {GetDidDocumentParams} args
 * @returns a did document
 */
export const getDidDocument = async (args: GetDidDocumentParams): Promise<DIDDocument> => {
  const { did, validAt } = args
  if (!did) {
    throw new Error('did parameter is required')
  }
  const query = validAt ? `?valid_at=${validAt}`: ''
  return await (await fetch(`https://api-pilot.ebsi.eu/did-registry/v5/identifiers/${did}${query}`)).json()
}

/**
 * listDidDocuments - Returns a list of identifiers.
 * @param {GetDidDocumentsParams} args
 * @returns a list of identifiers
 */
export const listDidDocuments = async (args: GetDidDocumentsParams): Promise<GetDidDocumentsResponse> => {
  const { offset, size, controller } = args
  const params: string[] = []
  if (offset) {
    params.push(`page[after]=${offset}`)
  }
  if (size) {
    params.push(`page[size]=${size}`)
  }
  if (controller) {
    params.push(`controller=${controller}`)
  }
  const query = `?${params.filter(Boolean).join('&')}`
  return await (await fetch(`https://api-pilot.ebsi.eu/did-registry/v5/identifiers${query}`)).json()
}
