import { Headers } from 'cross-fetch'
import {
  AddVerificationMethodParams,
  AddVerificationMethodRelationshipParams,
  InsertDidDocumentParams,
  SendSignedTransactionArgs,
  UpdateBaseDocumentParams,
} from '../types'

/**
 * @constant {string} jsonrpc
 */
const jsonrpc = '2.0' // optional param of plugin?
const baseUrl = 'https://api-pilot.ebsi.eu/did-registry/v5/jsonrpc' // optional param of plugin?
const token = '' // optional param of plugin?

/**
 * Call to build an unsigned transaction to insert a new DID document. Requires an access token with "didr_invite" or
 * "didr_write" scope.
 * @param {{ id: InsertDidDocumentParams[], id: number }} args
 */
export const insertDidDocument = async (args: { params: InsertDidDocumentParams[]; id: number }): Promise<Response> => {
  const { params, id } = args
  const options = {
    method: 'POST',
    headers: new Headers({
      Authorization: 'Bearer ' + token,
    }),
    body: JSON.stringify({
      jsonrpc,
      method: 'insertDidDocument',
      params,
      id,
    }),
  }
  return await (await fetch(baseUrl, options)).json()
}

/**
 * Call to build an unsigned transaction to update the base document of an existing DID. Requires an access token with
 * "didr_write" scope.
 * @param {{ params: UpdateBaseDocumentParams[], id:number }} args
 */
export const updateBaseDocument = async (args: { params: UpdateBaseDocumentParams; id: number }): Promise<Response> => {
  const { params, id } = args
  const options = {
    method: 'POST',
    headers: new Headers({
      Authorization: 'Bearer ' + token,
    }),
    body: JSON.stringify({
      jsonrpc,
      method: 'updateBaseDocument',
      params,
      id,
    }),
  }
  return await (await fetch(baseUrl, options)).json()
}

/**
 * Call to build an unsigned transaction to add a verification method. Requires an access token with "didr_write" scope.
 * @param {{ params: AddVerificationMethodParams[], id:number }} args
 */
export const addVerificationMethod = async (args: { params: AddVerificationMethodParams[]; id: number }): Promise<Response> => {
  const { params, id } = args
  const options = {
    method: 'POST',
    headers: new Headers({
      Authorization: 'Bearer ' + token,
    }),
    body: JSON.stringify({
      jsonrpc,
      method: 'addVerificationMethod',
      params,
      id,
    }),
  }
  return await (await fetch(baseUrl, options)).json()
}

/**
 * Call to build an unsigned transaction to add a verification relationship. Requires an access token with "didr_write" scope.
 * @param {{ params: AddVerificationMethodRelationshipParams[], id: number }} args
 */
export const addVerificationMethodRelationship = async (args: {
  params: AddVerificationMethodRelationshipParams[]
  id: number
}): Promise<Response> => {
  const { params, id } = args
  const options = {
    method: 'POST',
    headers: new Headers({
      Authorization: 'Bearer ' + token,
    }),
    body: JSON.stringify({
      jsonrpc,
      method: 'addVerificationMethodRelationship',
      params,
      id,
    }),
  }
  return await (await fetch(baseUrl, options)).json()
}

/**
 * Call to send a signed transaction to the blockchain. Requires an access token with "didr_invite" or "didr_write" scope.
 * @param {{ params: SendSignedTransactionArgs[], id: number }} args
 */
export const sendSignedTransaction = async (args: { params: SendSignedTransactionArgs[]; id: number }): Promise<Response> => {
  const { params, id } = args
  const options = {
    method: 'POST',
    headers: new Headers({
      Authorization: 'Bearer ' + token,
    }),
    body: JSON.stringify({
      jsonrpc,
      method: 'sendSignedTransaction',
      params,
      id,
    }),
  }
  return await (await fetch(baseUrl, options)).json()
}

// Key rotation?
