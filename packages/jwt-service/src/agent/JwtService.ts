import { IAgentPlugin } from '@veramo/core'
import {
  createJwsCompact,
  CreateJwsCompactArgs,
  CreateJwsFlattenedArgs,
  CreateJwsJsonArgs,
  createJwsJsonFlattened,
  createJwsJsonGeneral,
  IJwsValidationResult,
  IJwtService,
  IRequiredContext,
  JwsCompactResult,
  JwsJsonFlattened,
  JwsJsonGeneral,
  PreparedJwsObject,
  prepareJwsObject,
  schema,
  verifyJws,
  VerifyJwsArgs,
} from '..'

/**
 * @public
 */
export class JwtService implements IAgentPlugin {
  readonly schema = schema.IJwtService
  readonly methods: IJwtService = {
    jwtPrepareJws: this.jwtPrepareJws.bind(this),
    jwtCreateJwsJsonGeneralSignature: this.jwtCreateJwsJsonGeneralSignature.bind(this),
    jwtCreateJwsJsonFlattenedSignature: this.jwtCreateJwsJsonFlattenedSignature.bind(this),
    jwtCreateJwsCompactSignature: this.jwtCreateJwsCompactSignature.bind(this),
    jwtVerifyJwsSignature: this.jwtVerifyJwsSignature.bind(this),
  }

  private async jwtPrepareJws(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<PreparedJwsObject> {
    return await prepareJwsObject(args, context)
  }

  private async jwtCreateJwsJsonGeneralSignature(args: CreateJwsJsonArgs, context: IRequiredContext): Promise<JwsJsonGeneral> {
    return await createJwsJsonGeneral(args, context)
  }

  private async jwtCreateJwsJsonFlattenedSignature(args: CreateJwsFlattenedArgs, context: IRequiredContext): Promise<JwsJsonFlattened> {
    return await createJwsJsonFlattened(args, context)
  }

  private async jwtCreateJwsCompactSignature(args: CreateJwsCompactArgs, context: IRequiredContext): Promise<JwsCompactResult> {
    // We wrap it in a json object for remote REST calls
    return { jwt: await createJwsCompact(args, context) }
  }

  private async jwtVerifyJwsSignature(args: VerifyJwsArgs, context: IRequiredContext): Promise<IJwsValidationResult> {
    return await verifyJws(args, context)
  }
}
