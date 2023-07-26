import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import { Issuer } from "./issuer";
import { SessionStorage, SessionData } from "@remix-run/server-runtime";

interface OIDCStrategyVerifyOptions {}

export class OIDCStrategy<User> extends Strategy<
  User,
  OIDCStrategyVerifyOptions
> {
  name = "oidc";

  constructor(
    protected issuer: Issuer | string | URL,
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
      this.issuer instanceof Issuer
        ? this.issuer
        : await Issuer.discover(this.issuer);

    throw new Error("Method not implemented.");
  }
}
