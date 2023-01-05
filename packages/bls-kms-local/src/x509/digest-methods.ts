import { hash as sha256 } from '@stablelib/sha256'
import { hash as sha512 } from '@stablelib/sha512'
import * as u8a from 'uint8arrays'

export type DigestMethodName = 'sha256' | 'sha512'
export type TDigestMethod = (input: string) => string

export const digestMethodParams = (name: DigestMethodName): { digestName: DigestMethodName; digestMethod: TDigestMethod } => {
  if (name === 'sha256') {
    return { digestName: 'sha256', digestMethod: sha256DigestMethod }
  } else {
    return { digestName: 'sha512', digestMethod: sha512DigestMethod }
  }
}

const sha256DigestMethod = (input: string): string => {
  return u8a.toString(sha256(u8a.fromString(input, 'utf-8')), 'base16')
}

const sha512DigestMethod = (input: string): string => {
  return u8a.toString(sha512(u8a.fromString(input, 'utf-8')), 'base16')
}
