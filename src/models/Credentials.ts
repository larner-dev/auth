import { Db, Model, ModelParams, Transactable } from "@larner.dev/db";
import { compare, hash } from "bcrypt";
import { HTTPError } from "@larner.dev/http-codes";
import { randomBytes } from "crypto";

export enum CredentialType {
  Password = "Password",
  ThirdParty = "ThirdParty",
  SessionToken = "SessionToken",
  PriveledgedToken = "PrivilegedToken",
}

export type Credential = {
  id: number;
  created_at: Date;
  user_id: string;
  secret: string;
  type: CredentialType;
  expires_at: Date | null;
};

interface ConstructorArgs extends Partial<ModelParams<Credential>> {
  db: Db;
  saltRounds?: {
    [key in CredentialType]: number;
  };
}

export class CredentialModel extends Model<Credential> {
  private saltRounds: { [key in CredentialType]: number };
  constructor(args: ConstructorArgs) {
    super({
      table: args.table || "credentials",
      getCreatedField: args.getCreatedField || (() => "created_at"),
      getDeletedField: args.getDeletedField || (() => null),
      getIdField: args.getIdField || (() => "id"),
      getUpdatedField: args.getUpdatedField || (() => null),
      db: args.db,
      parse: args.parse,
    });
    this.saltRounds = {
      [CredentialType.Password]: 10,
      [CredentialType.ThirdParty]: 0,
      [CredentialType.SessionToken]: 1,
      [CredentialType.PriveledgedToken]: 10,
      ...(args.saltRounds || {}),
    };
  }
  async validateCredential(
    data: { userId: string; type: CredentialType; token: string },
    opts: Required<Transactable>
  ): Promise<boolean> {
    const { userId, type, token } = data;
    const creds = await opts.query<Credential>(
      "select secret from credentials where user_id = :userId and type = :type and (expires_at is null or expires_at > now())",
      { userId, type }
    );
    return (
      await Promise.all(creds.rows.map(({ secret }) => compare(token, secret)))
    ).some((a) => a);
  }
  async validateCredentialOrThrow(
    data: { userId: string; type: CredentialType; token: string },
    opts: Required<Transactable>
  ): Promise<void> {
    if (!(await this.validateCredential(data, opts))) {
      throw new HTTPError.Unauthorized("UNAUTHORIZED");
    }
  }
  async generateToken(
    type: CredentialType.SessionToken | CredentialType.PriveledgedToken,
    length = 32
  ): Promise<{ token: string; hash: string }> {
    const token: string = await new Promise((resolve) =>
      randomBytes(length, (err, buff) => resolve(buff.toString("base64url")))
    );
    const secret = await hash(token, this.saltRounds[type]);
    return { token, hash: secret };
  }
  async generateAndSaveToken(
    userId: string,
    type: CredentialType.SessionToken | CredentialType.PriveledgedToken,
    maxAgeMinutes: number | null = 525600,
    length = 32,
    trx?: Transactable
  ): Promise<string> {
    const { token, hash: secret } = await this.generateToken(type, length);
    let expiresAt = null;
    if (maxAgeMinutes) {
      expiresAt = new Date(Date.now() + maxAgeMinutes * 60 * 1000);
    }
    await this.save(
      {
        user_id: userId,
        type,
        secret,
        expires_at: expiresAt,
      },
      trx
    );
    return token;
  }
  async setPassword(
    data: {
      password: string;
      userId: string;
      expiresAt?: Date;
    },
    opts: Required<Transactable>
  ) {
    await this.hardDelete(
      {
        user_id: data.userId,
        type: CredentialType.Password,
      },
      opts
    );
    const secret = await hash(
      data.password,
      this.saltRounds[CredentialType.Password]
    );
    await this.save({
      created_at: new Date(),
      user_id: data.userId,
      secret,
      type: CredentialType.Password,
      expires_at: data.expiresAt || null,
    });
  }
}
