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
import { type ClientOptions } from "./client";

interface OIDCStrategyVerifyOptions {}

export class OIDCStrategy<User> extends Strategy<
  User,
  OIDCStrategyVerifyOptions
> {
  name = "oidc";

  constructor(
    protected options: ClientOptions & {
      issuer: Issuer | string | URL;
    },
    verify: StrategyVerifyCallback<User, OIDCStrategyVerifyOptions>
  ) {
    super(verify);
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage<SessionData, SessionData>,
    options: AuthenticateOptions
  ): Promise<User> {
    let issuer =
      this.options.issuer instanceof Issuer
        ? this.options.issuer
        : await Issuer.discover(this.options.issuer);

    let client = issuer.client(this.options);

    let url = client.authorizationUrl({ state: "random" });

    throw redirect(url.toString());
  }
}
