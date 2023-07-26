import { z } from "zod";
import type { Issuer } from "./issuer";

export interface ClientOptions {
  clientID: string;
  clientSecret?: string;
  redirectUri: string;
  responseType: ResponseType;
}

export class Client {
  #issuer: Issuer;
  #options: ClientOptions;

  constructor(issuer: Issuer, options: ClientOptions) {
    this.#issuer = issuer;
    this.#options = options;
  }

  authorizationUrl({
    redirectUri = this.#options.redirectUri,
    responseType = this.#options.responseType,
    scope = ["openid"],
    ...options
  }: AuthenticationRequestParams): URL {
    let result = AuthenticationRequestParamsSchema.safeParse({
      redirectUri,
      responseType,
      scope,
      ...options,
    });

    if (!result.success) {
      throw new Error("Invalid arguments for Client#authorizationUrl", {
        cause: result.error,
      });
    }

    let issuer = this.#issuer.metadata;

    let url = new URL(issuer.authorization_endpoint);

    // required
    url.searchParams.set("response_type", responseType);
    url.searchParams.set(
      "client_id",
      options.clientID ?? this.#options.clientID
    );
    url.searchParams.set("scope", scope.join(" "));
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", options.state);

    // optionals
    if (options.responseMode) {
      url.searchParams.set("response_mode", options.responseMode);
    }
    if (options.nonce) url.searchParams.set("nonce", options.nonce);
    if (options.display) url.searchParams.set("display", options.display);
    if (options.prompt) url.searchParams.set("prompt", options.prompt);
    if (options.maxAge) {
      url.searchParams.set("max_age", options.maxAge.toString());
    }
    if (options.uiLocales) {
      url.searchParams.set("ui_locales", options.uiLocales);
    }
    if (options.idTokenHint) {
      url.searchParams.set("id_token_hint", options.idTokenHint);
    }
    if (options.loginHint) {
      url.searchParams.set("login_hint", options.loginHint);
    }
    if (options.acrValues) {
      url.searchParams.set("acr_values", options.acrValues);
    }

    return url;
  }

  async userinfo(
    accessToken: string,
    options: {
      method: "GET" | "POST";
      via: "header" | "body";
    } = { method: "GET", via: "header" }
  ): Promise<UserInfo> {
    let method = (options.method ?? "GET").toUpperCase();

    if (options.method !== "GET" && options.method !== "POST") {
      throw new TypeError("Client#userinfo method can only be POST or a GET.");
    }

    if (options.via === "body" && options.method === "GET") {
      throw new Error("Cannot send access token in body with GET method.");
    }

    let issuer = this.#issuer.metadata;

    let url = new URL(issuer.userinfo_endpoint);

    let headers = new Headers();
    let init: RequestInit = { method, headers };

    if (options.via === "header") {
      headers.set("authorization", `Bearer ${accessToken}`);
    }

    if (options.via === "body") {
      headers.set("content-type", "application/x-www-form-urlencoded");
      let body = new URLSearchParams();
      body.append("access_token", accessToken);
      init.body = body;
    }

    let response = await fetch(url, init);

    if (!response.ok) throw new Error("Failed to fetch userinfo");

    return await UserInfoSchema.promise().parse(response.json());
  }

  async refresh(refreshToken: string) {
    let body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.#options.clientID,
      refresh_token: refreshToken,
    });

    if (this.#options.clientSecret) {
      body.set("client_secret", this.#options.clientSecret);
    }

    let issuer = this.#issuer.metadata;
    issuer.token_endpoint;

    let response = await fetch(issuer.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!response.ok) throw new Error("Failed to refresh token.");

    return z
      .object({
        access_token: z.string(),
        expires_in: z.literal(86400),
        scope: z
          .string()
          .transform((scope) => scope.split(" "))
          .pipe(ScopeSchema.array()),
        id_token: z.string(),
        token_type: z.literal("Bearer"),
      })
      .promise()
      .parse(response.json());
  }
}

const UserInfoSchema = z
  .object({
    sub: z.string(),
    name: z.string().optional(),
    given_name: z.string().optional(),
    family_name: z.string().optional(),
    middle_name: z.string().optional(),
    nickname: z.string().optional(),
    preferred_username: z.string().optional(),
    profile: z.string().optional(),
    picture: z.string().optional(),
    website: z.string().optional(),
    email: z.string().optional(),
    email_verified: z.boolean().optional(),
    gender: z.string().optional(),
    birthdate: z.string().optional(),
    zoneinfo: z.string().optional(),
    locale: z.string().optional(),
    phone_number: z.string().optional(),
    updated_at: z.number().optional(),
    address: z
      .object({
        formatted: z.string().optional(),
        street_address: z.string().optional(),
        locality: z.string().optional(),
        region: z.string().optional(),
        postal_code: z.string().optional(),
        country: z.string().optional(),
      })
      .passthrough(),
  })
  .passthrough();

export type UserInfo = z.infer<typeof UserInfoSchema>;

const ResponseTypeSchema = z.enum([
  "code",
  "token",
  "id_token",
  "code token",
  "code id_token",
  "token id_token",
  "code token id_token",
  "none",
]);

type ResponseType = z.infer<typeof ResponseTypeSchema>;

const ScopeSchema = z.enum([
  "openid",
  "email",
  "profile",
  "address",
  "phone",
  "offline_access",
]);

const AuthenticationRequestParamsSchema = z.object({
  scope: ScopeSchema.array()
    .refine((scopes) => scopes.includes("openid"), {
      message: "openid scope is required",
    })
    .optional(),
  responseType: z
    .enum([
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
      "none",
    ])
    .optional(),
  clientID: z.string().optional(),
  redirectUri: z.string().url().optional(),
  state: z.string(),
  responseMode: z.string().optional(),
  nonce: z.string().optional(),
  display: z.enum(["page", "popup", "touch", "wap"]).optional(),
  prompt: z.enum(["none", "login", "consent", "select_account"]).optional(),
  maxAge: z.number().optional(),
  uiLocales: z.string().optional(),
  idTokenHint: z.string().optional(),
  loginHint: z.string().optional(),
  acrValues: z.string().optional(),
});

type AuthenticationRequestParams = z.infer<
  typeof AuthenticationRequestParamsSchema
>;
