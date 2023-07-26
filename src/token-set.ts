import { z } from "zod";

export class TokenSet {
  public access_token!: string;
  public token_type!: string;
  public id_token!: string;
  public refresh_token!: string;
  public expires_at!: number;
  public session_state?: string;
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

  set expires_in(value: number) {
    this.expires_at = this.now() + Number(value);
  }

  get expires_in() {
    return Math.max(...[this.expires_at - this.now(), 0]);
  }

  expired() {
    return this.expiresIn === 0;
  }

  claims() {
    if (!this.id_token) throw new TypeError("id_token not present in TokenSet");
    let [, payload] = this.id_token.split(".");
    return JSON.parse(Buffer.from(payload, "base64").toString("utf-8"));
  }

  private now() {
    return Math.floor(Date.now() / 1000);
  }
}

const TokenSetValueSchema = z
  .object({
    access_token: z.string(),
    token_type: z.string(),
    id_token: z.string(),
    refresh_token: z.string(),
    expires_at: z.number(),
    session_state: z.string().optional(),
  })
  .passthrough();

type TokenSetValue = z.infer<typeof TokenSetValueSchema>;
