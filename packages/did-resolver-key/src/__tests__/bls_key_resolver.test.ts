import { Resolver } from 'did-resolver'
import { DID_LD_JSON, getResolver } from '../index'
import * as fs from 'fs'

describe('@sphereon/ssi-sdk-ext-key-did-resolver', () => {
  it('should resolve a BLS did:key', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const doc = await resolver.resolve(
      'did:key:zUC7Gc59EawPuAbe1gcbmpTtYeyRvRLUsCfkmHwmNaiQyQtQp9f4G4KHurpHaa6QUvm1mL1rZvKXQWpfRcTBfLsstL2kmMN3rkFSzYuzbxwD4LespdY8NKdsghxeiRNtNSbzKic'
    )
    expect(doc).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/bls_did_doc.json`, { encoding: 'utf-8' })))
  })
  it('should resolve a Ed25519 did:key', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const doc = await resolver.resolve('did:key:z6MkkDYR2LLa6tDBXVEuxcU4pqvHggz36oQESE9fc9jK6mAt')
    expect(doc).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/ed25519_did_doc.json`, { encoding: 'utf-8' })))
  })
  it('should resolve a secp256k1 did:key', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const doc = await resolver.resolve('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme')
    expect(doc).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/secp256k1_did_doc.json`, { encoding: 'utf-8' })))
  })
  it('should resolve a jcs JWK did:key', async () => {
    const resolver = new Resolver({ ...getResolver() })
    const doc = await resolver.resolve(
      'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r',
      { accept: DID_LD_JSON }
    )
    expect(doc).toEqual(JSON.parse(fs.readFileSync(`${__dirname}/fixtures/jwk_jcs_did_doc.json`, { encoding: 'utf-8' })))
  })
})
