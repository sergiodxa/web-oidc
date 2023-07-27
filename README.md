# Web OIDC

An OpenID Connect client for web applications built completely using standard Web APIs.

> This package is still a work in progress.

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
  redirectUri: "https://www.company.tld/auth/callback",
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
  redirectUri: "https://www.company.tld/auth/callback",
  responseType: "code id_token",
});
```

This will instantiate a client with the issuer's configuration.

With a Client instance, we can start handling the authentication flow.

```ts
// The `Generator.state()` method is a helper to generate a cryptographically
// secure random string
import { Generator } from "web-oidc";

let url = client.authorizationUrl({ state: Generator.state() });
```

This will generate a URL that you can redirect the user to start the flow.

### Fetch user info

You can use the `Client#userinfo` method to fetch the user's profile from the IdP.

```ts
let userinfo = await client.userinfo("accessToken");
```

### Use refresh tokens

If you're keeping the access and refresh tokens around, you can use the `Client#refresh` method to get a new access token when it expires.

```ts
let { accessToken, refreshToken, extraParams } = await client.refresh(
  oldAccessToken
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
      redirectUri: "https://www.company.tld/auth/callback",
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

### Use with Hono

If you're building a Hono application, this packages exports a middleware you can use.

```ts
import { oidc, getOIDC } from "web-oidc/hono";

app = new Hono();

app.use(
  "*",
  oidc({
    issuer: "https://auth.company.tld",
    clientID: "CLIENT_ID",
    clientSecret: "CLIENT_SECRET",
    redirectUri: "https://www.company.tld/auth/callback",
    responseType: "code id_token",
    routes: {
      // You can customize the routes used to handle the login flow
      // These values are the default ones
      login: "/auth",
      callback: "/auth/callback",
    },
  })
);

app.get("/", async (ctx) => {
  // Check if the user is authenticated
  let isAuthenticated = oidc.isAuthenticated(ctx);
  if (isAuthenticated) return ctx.redirect("/profile");
  return ctx.html("<h1>Hello Hono</h1>");
});

// Require authentication for this route, by default it will redirect to routes.login
app.get(
  "/profile",
  oidc.authenticate({ failureRedirect: "/" }),
  async (ctx) => {
    // Get the user info
    let user = await oidc.user(ctx);
    return ctx.html(`<h1>Hello ${user.name}</h1>`);
  }
);
```

## Author

- [Sergio Xalambrí](https://sergiodxa.com)
