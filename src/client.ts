import { z } from "zod";
import { Issuer } from "./issuer";
import { TokenSet } from "./token-set";

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

  get issuer() {
    return this.#issuer;
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
    accessToken: string | TokenSet,
    options: {
      method: "GET" | "POST";
      via: "header" | "body";
    } = { method: "GET", via: "header" }
  ): Promise<UserInfo> {
    let endpoint = assert(this.#issuer, "userinfo_endpoint");

    let method = (options.method ?? "GET").toUpperCase();

    if (options.method !== "GET" && options.method !== "POST") {
      throw new TypeError("Client#userinfo method can only be POST or a GET.");
    }

    if (options.via === "body" && options.method === "GET") {
      throw new Error("Cannot send access token in body with GET method.");
    }

    let url = new URL(endpoint);

    let headers = new Headers();
    let init: RequestInit = { method, headers };

    let token =
      accessToken instanceof TokenSet ? accessToken.access_token : accessToken;

    if (options.via === "header") {
      headers.set("authorization", `Bearer ${token}`);
    }

    if (options.via === "body") {
      headers.set("content-type", "application/x-www-form-urlencoded");
      let body = new URLSearchParams();
      body.append("access_token", token);
      init.body = body;
    }

    let response = await fetch(url, init);

    if (!response.ok) {
      throw new Error("Failed to fetch userinfo", { cause: response });
    }

    return await UserInfoSchema.promise().parse(response.json());
  }

  async refresh(refreshToken: string | TokenSet) {
    let body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token:
        refreshToken instanceof TokenSet
          ? refreshToken.refresh_token
          : refreshToken,
    });

    return await this.grant(body);
  }

  async grant(body: URLSearchParams): Promise<TokenSet> {
    let endpoint = assert(this.#issuer, "token_endpoint");

    let headers: HeadersInit = {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    };

    body.set("client_id", this.#options.clientID);
    if (this.#options.clientSecret) {
      body.set("client_secret", this.#options.clientSecret);
    }

    let response = await fetch(endpoint, {
      method: "POST",
      headers,
      body,
    });

    if (!response.ok) {
      let body = await response.text();
      throw new Error("Failed to fetch token endpoint", { cause: body });
    }

    let result = await z
      .object({
        access_token: z.string(),
        expires_in: z.literal(86400),
        scope: z
          .string()
          .transform((scope) => scope.split(" "))
          .pipe(ScopeSchema.array()).transform((scopes) => scopes.join(" ")),
        id_token: z.string(),
        token_type: z.literal("Bearer"),
      })
      .promise()
      .parse(response.json());

    return new TokenSet(result);
  }

  async callbackParams(input: string | URL | Request) {
    let params: URLSearchParams;

    if (typeof input === "string") params = new URL(input).searchParams;
    else if (input instanceof URL) params = input.searchParams;
    else if (input instanceof Request) {
      let method = input.method.toUpperCase();
      if (method === "GET") params = new URL(input.url).searchParams;
      if (input.body === undefined) {
        throw new TypeError("Input Request must have a body if it's not a GET");
      }
      let request = new Request(input.url, input);
      params = new URLSearchParams(await request.text());
    } else throw new TypeError("Invalid input for Client#callbackParams");

    return params;
  }

  oauthCallback(
    redirectURL: URL,
    incoming: URLSearchParams,
    checks: {
      response_type?: ResponseType[];
      state?: string;
      nonce?: string;
    }
  ) {
    let stateUrl = incoming.get("state");

    if (incoming.has("state") && !checks.state) {
      throw new TypeError("Missing Client#callback checks.state");
    }

    if (!incoming.has("state") && checks.state) {
      throw new ReferenceError("Missing state on URL.");
    }

    if (incoming.get("state") !== checks.state) {
      throw new RangeError("State mismatch.", {
        cause: { expected: checks.state, actual: stateUrl },
      });
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS: Partial<
      Record<ResponseType, string[]>
    > = {
      code: ["code"],
      id_token: ["id_token"],
      token: ["access_token", "token_type"],
    };

    for (let type of checks.response_type ?? []) {
      if (type === "none") {
        if (
          incoming.has("code") ||
          incoming.has("id_token") ||
          incoming.has("access_token")
        ) {
          throw new RangeError(
            "Unexpected parameters for response_type none.",
            { cause: "Expected none, received code, id_token or access_token" }
          );
        }
      } else if (type in RESPONSE_TYPE_REQUIRED_PARAMS) {
        let requiredParams = RESPONSE_TYPE_REQUIRED_PARAMS[type] ?? [];
        for (let param of requiredParams) {
          if (!incoming.has(param)) {
            throw new ReferenceError(
              `Missing ${param} on URL for response_type ${type}.`
            );
          }
        }
      }
    }

    if (incoming.has("id_token")) {
      throw new Error("id_token flow not implemented");
    }

    if (incoming.has("access_token")) {
      throw new Error("token flow not implemented");
    }

    if (incoming.has("code")) {
      let params = new URLSearchParams({
        grant_type: "authorization_code",
        code: incoming.get("code")!,
        redirect_uri: redirectURL.toString(),
      });

      return this.grant(params);
    }

    throw new Error("No valid response_type found.");
  }

  static async register(
    issuer: Issuer | URL | string,
    options: {
      initialAccessToken?: string;
    } = {}
  ) {
    if (!(issuer instanceof Issuer)) {
      issuer = await Issuer.discover(issuer);
    }

    let endpoint = assert(issuer, "registration_endpoint");

    let headers = new Headers({
      accept: "application/json",
      "content-type": "application/json",
    });

    if (options.initialAccessToken) {
      headers.set("authorization", `Bearer ${options.initialAccessToken}`);
    }

    let response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(issuer.metadata),
    });

    if (!response.ok) {
      throw new Error(
        `Failed to register client for issuer ${issuer.metadata.issuer}`
      );
    }

    let body = await z
      .object({
        client_id: z.string(),
        client_secret: z.string(),
        redirect_uri: z.string().url(),
        response_type: ResponseTypeSchema,
      })
      .promise()
      .parse(response.json());

    return new Client(issuer, {
      clientID: body.client_id,
      clientSecret: body.client_secret,
      redirectUri: body.redirect_uri,
      responseType: body.response_type,
    });
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

function assert(issuer: Issuer, endpoint: keyof Issuer["metadata"]) {
  let value = issuer.metadata[endpoint];

  if (!value) {
    throw new TypeError(`${endpoint} must be configured on the issuer`);
  }
  if (typeof value !== "string") {
    throw new TypeError(`${endpoint} must be a string`);
  }

  return new URL(value);
}
