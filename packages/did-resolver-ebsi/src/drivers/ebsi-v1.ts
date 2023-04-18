import { DIDDocument, DIDResolutionOptions } from 'did-resolver'
import { fetch } from 'cross-fetch'

export const keyToDidDoc = async (did: string, contentType: string, options: DIDResolutionOptions): Promise<DIDDocument> => {
  const uri = didURI(did, options)
  console.log(uri)
  const doc = (await fetch(uri).then((res) => res.json())) as DIDDocument
  console.log(JSON.stringify(doc))
  return doc
}

const didURI = (did: string, options: DIDResolutionOptions) => {
  let registry = determineRegistry(options)
  if (registry.endsWith('/')) {
    registry = registry.substring(0, registry.length - 1)
  }
  if (!registry.includes('identifiers')) {
    registry += '/identifiers'
  }
  return `${registry}/${did}`
}

const determineRegistry = (options: DIDResolutionOptions): string => {
  if (options.registry && typeof options.registry === 'string') {
    return options.registry
  }
  return process.env.EBSI_DEFAULT_REGISTRY ?? 'https://api-pilot.ebsi.eu/did-registry/v4'
}
export default { keyToDidDoc }
