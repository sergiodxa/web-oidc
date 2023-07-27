import { z } from "zod";

export class TokenSet {
  public access_token!: string;
  public token_type!: string;
  public id_token!: string;
  public refresh_token!: string;
  public expires_in!: number;
  public scope!: z.infer<typeof ScopeSchema>[];
  [key: string]: TokenSetValue[keyof TokenSetValue];

  constructor(values: TokenSetValue) {
    let result = TokenSetValueSchema.safeParse(values);

    if (!result.success) {
      throw new Error("Invalid argument for TokenSet", { cause: result.error });
    }

    Object.assign(this, result.data);
    const { constructor, ...properties } = Object.getOwnPropertyDescriptors(
      this.constructor.prototype
    );

    Object.defineProperties(this, properties);
  }

  expired() {
    return this.expires_in === 0;
  }

  claims() {
    if (!this.id_token) throw new TypeError("id_token not present in TokenSet");
    let [, payload] = this.id_token.split(".");
    return JSON.parse(Buffer.from(payload, "base64").toString("utf-8"));
  }

  toJSON() {
    return {
      access_token: this.access_token,
      token_type: this.token_type,
      id_token: this.id_token,
      refresh_token: this.refresh_token,
      expires_in: this.expires_in,
      scope: this.scope.join(" "),
    };
  }

  toString() {
    return JSON.stringify(this);
  }
}

const ScopeSchema = z.enum([
  "openid",
  "email",
  "profile",
  "address",
  "phone",
  "offline_access",
]);

const TokenSetValueSchema = z
  .object({
    access_token: z.string(),
    expires_in: z.number(),
    scope: z
      .string()
      .transform((scope) => scope.split(" "))
      .pipe(ScopeSchema.array()),
    id_token: z.string(),
    token_type: z.literal("Bearer"),
  })
  .passthrough();

export type TokenSetValue = z.infer<typeof TokenSetValueSchema>;
