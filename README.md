# Web OIDC

An OpenID Connect client for web applications built completely using standard Web APIs.

## Installation

```sh
npm add web-oidc
```

## Usage

You can use the `Issuer.discover` method to discover the OpenID Connect issuer configuration.

```ts
import { Issuer } from "web-oidc";

const issuer = await Issuer.discover("https://auth.company.tld");
```

The `issuer` value will be a `Issuer` instance where you can later call `issuer.metadata` to access the configuration of the issuer.

With the issuer ready, we can instantiate a Client.

```ts
import { Client } from "web-oidc";
let client = new Client(issuer, {
  clientID: "CLIENT_ID",
  clientSecret: "CLIENT_SECRET",
  redirectUri: "https://company.tld/auth/callback",
  responseType: "code id_token",
});
```

Additionally, we can create the client directly from the issuer.

```ts
import { Issuer } from "web-oidc";

const issuer = await Issuer.discover("https://auth.company.tld");

let client = issuer.client({
  clientID: "CLIENT_ID",
  clientSecret: "CLIENT_SECRET",
  redirectUri: "https://company.tld/auth/callback",
  responseType: "code id_token",
});
```

This will instantiate a client with the issuer's configuration.

With a Client instance, we can start handling the authentication flow.

```ts
let url = client.authorizationUrl({ state: "random" });
```

This will generate a URL that you can redirect the user to start the flow.

---

You can use the `Client#userinfo` method to fetch the user's profile.

```ts
let userinfo = await client.userinfo("accessToken");
```

---

You can also refresh the access token with one line:

```ts
let { accessToken, refreshToken, extraParams } = await client.refreshToken(
  session.get("refreshToken")
);
```

### Use with Remix Auth

If you're building a Remix application and using Remix Auth, this packages exports a strategy you can use.

```ts
import { OIDCStrategy } from "web-oidc/remix";

authenticator.use(
  new OIDCStrategy(
    {
      issuer: "https://auth.company.tld",
      clientID: "CLIENT_ID",
      clientSecret: "CLIENT_SECRET",
      redirectUri: "https://company.tld/auth/callback",
      responseType: "code id_token",
    },
    async ({ profile, accessToken, refreshToken, extraParams }) => {
      return { profile, accessToken, refreshToken };
    }
  )
);
```

The `issuer` can be a string or URL similar to `Issuer.discover`, it could also be a `Issuer` instance if you already have one.

You can then use this strategy in your routes.

```ts
export async function action({ request }: DataFunctionArgs) {
  return await authenticator.authenticate("oidc", request, {
    successRedirect: "/home",
    failureRedirect: "/login",
  });
}
```

