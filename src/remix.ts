import {
  type AuthenticateOptions,
  Strategy,
  type StrategyVerifyCallback,
} from "remix-auth";
import { Issuer } from "./issuer";
import {
  type AppLoadContext,
  type SessionStorage,
  type SessionData,
  redirect,
} from "@remix-run/server-runtime";
import {
  UserInfo,
  type ClientOptions,
  type AuthenticationRequestParams,
} from "./client";
import { Generator } from "./generator";
import { TokenSet } from "./token-set";

interface OIDCStrategyVerifyOptions {
  context?: AppLoadContext;
  profile: UserInfo;
  tokens: TokenSet;
}

interface OIDCStrategyOptions extends Omit<ClientOptions, "responseType"> {
  authorizationParams: Omit<
    AuthenticationRequestParams,
    "clientID" | "responseType" | "redirectUri" | "state"
  >;
  issuer: Issuer | string | URL;
  sessionKeys?: { state?: `oidc:${string}` };
}

export class OIDCStrategy<User> extends Strategy<
  User,
  OIDCStrategyVerifyOptions
> {
  name = "oidc";

  private issuerPromise?: Promise<Issuer>;

  constructor(
    protected options: OIDCStrategyOptions,
    verify: StrategyVerifyCallback<User, OIDCStrategyVerifyOptions>
  ) {
    super(verify);
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage<SessionData, SessionData>,
    options: AuthenticateOptions
  ): Promise<User> {
    let url = new URL(request.url);
    let redirectURL = new URL(this.options.redirect_uri);

    if (url.pathname !== redirectURL.pathname) {
      let state = Generator.state();

      let session = await sessionStorage.getSession(
        request.headers.get("cookie")
      );

      session.set(this.options.sessionKeys?.state ?? "oidc:state", state);

      let client = await this.client;
      let url = client.authorizationUrl({
        state,
        ...this.options.authorizationParams,
      });

      throw redirect(url.toString(), {
        headers: { "set-cookie": await sessionStorage.commitSession(session) },
      });
    }

    try {
      let session = await sessionStorage.getSession(
        request.headers.get("cookie")
      );

      let stateSession = session.get(
        this.options.sessionKeys?.state ?? "oidc:state"
      );

      let client = await this.client;

      let params = await client.callbackParams(request);

      let tokens = await client.oauthCallback(redirectURL, params, {
        state: stateSession,
        response_type: "code",
      });

      let profile = await client.userinfo(tokens.access_token);

      let user = await this.verify({
        profile,
        tokens,
        context: options.context,
      });

      return await this.success(user, request, sessionStorage, options);
    } catch (exception) {
      // Allow responses to pass-through
      if (exception instanceof Response) throw exception;
      if (exception instanceof Error) {
        return await this.failure(
          exception.message,
          request,
          sessionStorage,
          options,
          exception
        );
      }
      if (typeof exception === "string") {
        return await this.failure(
          exception,
          request,
          sessionStorage,
          options,
          new Error(exception)
        );
      }
      return await this.failure(
        "Unknown error",
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(exception, null, 2))
      );
    }
  }

  get issuer() {
    if (this.issuerPromise) return this.issuerPromise;

    if (this.options.issuer instanceof Issuer) {
      this.issuerPromise = Promise.resolve(this.options.issuer);
      return this.issuerPromise;
    }

    this.issuerPromise = Issuer.discover(this.options.issuer);
    return this.issuerPromise;
  }

  get client() {
    return this.issuer.then((issuer) =>
      issuer.client({ ...this.options, response_type: "code" })
    );
  }
}
