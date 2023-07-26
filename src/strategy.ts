import {
  type AuthenticateOptions,
  Strategy,
  type StrategyVerifyCallback,
} from "remix-auth";
import { Issuer } from "./issuer";
import {
  type SessionStorage,
  type SessionData,
  redirect,
} from "@remix-run/server-runtime";
import { Client, type ClientOptions } from "./client";

interface OIDCStrategyVerifyOptions {}

export class OIDCStrategy<User> extends Strategy<
  User,
  OIDCStrategyVerifyOptions
> {
  name = "oidc";

  private issuerPromise?: Promise<Issuer>;

  constructor(
    protected options: ClientOptions & { issuer: Issuer | string | URL },
    verify: StrategyVerifyCallback<User, OIDCStrategyVerifyOptions>
  ) {
    super(verify);
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage<SessionData, SessionData>,
    options: AuthenticateOptions
  ): Promise<User> {
    let client = await this.client;

    let session = await sessionStorage.getSession(
      request.headers.get("cookie")
    );

    let state = crypto.randomUUID();

    session.set("oidc:state", state);

    let url = client.authorizationUrl({ state });

    throw redirect(url.toString(), {
      headers: { "set-cookie": await sessionStorage.commitSession(session) },
    });
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
    return this.issuer.then((issuer) => issuer.client(this.options));
  }
}
