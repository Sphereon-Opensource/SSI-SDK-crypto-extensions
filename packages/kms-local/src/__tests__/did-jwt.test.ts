import {SphereonKeyManagementSystem} from "../SphereonKeyManagementSystem";
import {MemoryPrivateKeyStore} from "@veramo/key-manager";
import {ManagedKeyInfo} from "@veramo/core";
import * as u8a from 'uint8arrays'
import {generatePrivateKeyHex} from "@sphereon/ssi-sdk-ext.key-utils";

const UNSIGNED_JWT = 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IlBTMjU2Iiwia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSlNVMEVpTENKdUlqb2laakkzYTJoMk0wMU5ZM2xVYm1wT1ZqSTBkV1pMUlV0Qk5qQklOek5oZW1oa2NpMVVjVXhVUm1kYVp5MDJVemMyZDFBNVpqRkhNRm94UW5OcFYyeFlkRWRYTlRaR2RqWkpSRTUyYW5CVVh6Tm5aa0ZJVjB0M1FsQTNhM3BXT1RKc1UyZHlWVTl3ZDBoWWNtTmpUa3RGUkRGV1dHOHdRMFJrVFd0MVdHWTNkWGMwV2pscVNIRk1aM3BaYUdFNU5XdGxXSFo0TjNOSFRrdENRVEJrVFhwek5tNUpSa2RpU0ZkT1pFSnhOVEZWVm01V1lWRTJaa1ZsZG05U05XUktVWFJFTFV0VmVHaDRNV0psUWxSbFkxbGhjeTF4TVVwa1lqQkJMV0l6VVRKNFNDMXNTRzFhVjJwdFJWOWtSVVU1U0VseFRGZFNXRGRQZEZGNWJqVldVMGxRTVdOUlZYUllPRlpQYUVsM2JHTldOM0phWWpGTExYaGlhazlhYURkcU9IQkdNakJCTTFBM2FrRnNjRkV0VlUxaFdrTmxXa3RsT1hBMldtcFdla1JMWHpBNU9WZFBXWHBxZW1KT2FYUTJWbDlTTmxSRFNHSlJJaXdpWlNJNklrRlJRVUlpZlEjMCJ9.eyJpYXQiOjE3MDYwMjEyNzMsImV4cCI6MzQxMjA0MjYwNSwiYXVkIjoiaHR0cHM6Ly9lc2lnbmV0LmNvbGxhYi5tb3NpcC5uZXQiLCJub25jZSI6IlRnVWY0Z3dPaHZrTzV3eHVZNE1lIiwiaXNzIjoiTVVxMUg1TTRPQnI5ZnhTQzJmSnJZNGZlbFJteHREdzRpUmxzMmxCWlF6SSIsImp0aSI6ImVlNTYwMTg0LTU1YjUtNDkzNC1hZGI0LTBhMWFkZGE3ZGQzZSJ9'
describe('JWT test with RSA', () => {
    const kms = new SphereonKeyManagementSystem(new MemoryPrivateKeyStore())

    let key: ManagedKeyInfo
    it('should import pk', async () => {
        const privateKeyHex = await generatePrivateKeyHex('RSA')
        key = await kms.importKey(
            {
                kid: 'test',
                privateKeyHex: privateKeyHex,
                type: 'RSA',
                meta: {algorithms: ['PS256']}
            })
        expect(key.type).toEqual('RSA')
        console.log('publicKeyHex:', key.publicKeyHex)
    })

    const data = u8a.fromString(UNSIGNED_JWT, 'utf-8')
    let signature: string
    let jwt: string
    it('should sign & verify JWT', async () => {
        signature = await kms.sign({keyRef: key, data, algorithm: 'PS256'})
        const result = await kms.verify({
            type: "RSA",
            publicKeyHex: key.publicKeyHex,
            data,
            signature
        })
        expect(result).toBeTruthy()

        jwt = [UNSIGNED_JWT, signature].join('.')
        console.log('JWT:', jwt)
    })

})
