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

export type PublicCredential = {
  id: number;
  created_at: Date;
  user_id: string;
  type: CredentialType;
  expires_at: Date | null;
};

export type Credential = PublicCredential & {
  secret: string;
};

interface ConstructorArgs extends Partial<ModelParams<Credential>> {
  db: Db;
  saltRounds?: {
    [key in CredentialType]: number;
  };
}

interface GenerateAndSaveTokenArgs {
  userId: string;
  type: CredentialType.SessionToken | CredentialType.PriveledgedToken;
  maxAgeMinutes?: number;
  length?: 32;
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
    args: GenerateAndSaveTokenArgs,
    opts?: Transactable
  ): Promise<string> {
    const { userId, type } = args;
    const maxAgeMinutes = args.maxAgeMinutes || 525600;
    const length = args.length || 32;
    const { token, hash: secret } = await this.generateToken(type, length);
    let expiresAt = null;
    if (maxAgeMinutes) {
      expiresAt = new Date(Date.now() + maxAgeMinutes * 60 * 1000);
    }
    const cred = await this.saveAndFetch(
      {
        user_id: userId,
        type,
        secret,
        expires_at: expiresAt,
      },
      opts
    );
    return `${token}.${cred.id}`;
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
  async validatePassword(
    data: { userId: string; password: string },
    opts?: Transactable
  ): Promise<boolean> {
    const { userId, password } = data;
    const cred = await this.fetch(
      {
        user_id: userId,
        type: CredentialType.Password,
      },
      opts
    );
    if (!cred) {
      return false;
    }
    return await compare(password, cred.secret);
  }
  async validatePasswordOrThrow(
    data: { userId: string; password: string },
    opts?: Transactable
  ): Promise<boolean> {
    const { userId, password } = data;
    const cred = await this.fetch(
      {
        user_id: userId,
        type: CredentialType.Password,
      },
      opts
    );
    if (!cred) {
      return false;
    }
    return await compare(password, cred.secret);
  }
  async validateToken(
    data: {
      type: CredentialType.SessionToken | CredentialType.PriveledgedToken;
      token: string;
    },
    opts?: Transactable
  ): Promise<PublicCredential | null> {
    const { type } = data;
    const pieces = data.token.split(".");
    if (pieces.length !== 2) {
      return null;
    }
    const hash = pieces[0];
    const credId = parseInt(pieces[1]);
    if (isNaN(credId)) {
      return null;
    }
    const cred = await this.fetch(
      {
        id: credId,
        type,
      },
      opts
    );
    if (!cred) {
      return null;
    }
    if (await compare(hash, cred.secret)) {
      return {
        id: cred.id,
        created_at: cred.created_at,
        user_id: cred.user_id,
        type: cred.type,
        expires_at: cred.expires_at,
      };
    }
    return null;
  }
  async validateTokenOrThrow(
    data: {
      type: CredentialType.SessionToken | CredentialType.PriveledgedToken;
      token: string;
    },
    opts?: Transactable
  ): Promise<PublicCredential> {
    const cred = await this.validateToken(data, opts);
    if (!cred) {
      throw new HTTPError.Unauthorized("UNAUTHORIZED");
    }
    return cred;
  }
}
