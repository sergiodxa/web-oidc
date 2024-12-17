# Web OIDC

> [!WARN]
> Most of the features here are now supported by the OAuth2Strategy for Remix Auth and the Arctic package used internally by that strategy, this package is now depreacted and if you use it with Remix Auth I recommend you to use the OAuth2Strategy.

An OpenID Connect client for web applications built completely using standard Web APIs.

> **Note**: This package is a port of [`openid-client`](https://github.com/panva/node-openid-client) but only using standard Web APIs.

> **Warning**: This package is still a work in progress and should not be used in production.

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
  client_id: "CLIENT_ID",
  client_secret: "CLIENT_SECRET",
  redirect_uri: "https://www.company.tld/auth/callback",
  response_type: "code id_token",
});
```

Additionally, we can create the client directly from the issuer.

```ts
import { Issuer } from "web-oidc";

const issuer = await Issuer.discover("https://auth.company.tld");

let client = issuer.client({
  client_id: "CLIENT_ID",
  client_secret: "CLIENT_SECRET",
  redirect_uri: "https://www.company.tld/auth/callback",
  response_type: "code id_token",
});
```

This will instantiate a client with the issuer's configuration.

With a Client instance, we can start handling the authentication flow.

```ts
// The `Generator.state()` method is a helper to generate a cryptographically
// secure random string
import { Generator } from "web-oidc";

let state = Generator.state(); // keep this in a cookie/session
let url = client.authorizationUrl({ state });
```

This will generate a URL that you can redirect the user to start the flow.

Once the user is back on your callback URL, you can use the `Client#callbackParams` and `Client#oauthCallback` methods to handle the request.

```ts
let params = await client.callbackParams(request);
let tokens = await client.oauthCallback(new URL(request.url), params, {
  state, // read this from where you stored it
  response_type: "code",
});
```

You can then use the `Client#userinfo` method to fetch the user's profile from the IdP.

```ts
let userinfo = await client.userinfo(tokens.access_token);
```

And if you're keeping the access and refresh tokens around, you can use the `Client#refresh` method to get a new access token when it expires.

```ts
let { accessToken, refreshToken, extraParams } = await client.refresh(
  tokens.refresh_token
);
```

### Use with Remix Auth

If you're building a Remix application and using Remix Auth, this package exports a strategy you can use.

```ts
import { OIDCStrategy } from "web-oidc/remix";

authenticator.use(
  new OIDCStrategy(
    {
      issuer: "https://auth.company.tld",
      client_id: "CLIENT_ID",
      client_secret: "CLIENT_SECRET",
      redirect_uri: "https://www.company.tld/auth/callback",
      response_type: "code id_token",
    },
    async ({ profile, tokens }) => {
      return { profile, tokens };
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

If you plan to keep the tokens saved, you can save the strategy into a variable.

```ts
import { OIDCStrategy } from "web-oidc/remix";
import { Issuer } from "web-oidc";

let strategy = new OIDCStrategy<User>(
  {
    issuer: "https://auth.company.tld",
    client_id: "CLIENT_ID",
    client_secret: "CLIENT_SECRET",
    redirect_uri: "https://www.company.tld/auth/callback",
    response_type: "code id_token",
  },
  async ({ profile, tokens }) => {
    return { profile, tokens };
  }
);

authenticator.use(strategy);
```

Then, you can access the Issuer and Client instances with:

```ts
let issuer = await strategy.issuer;
let client = await strategy.client;
```

The return value of both is a promise because (unless you pass an Issuer instance to the strategy) the strategy needs to discover the issuer configuration dynamically first and this only happens the first time it's needed.

### Use with Hono

If you're building a Hono application, this package exports a middleware you can use.

```ts
import { oidc } from "web-oidc/hono";

app = new Hono();

app.use(
  "*",
  oidc({
    issuer: "https://auth.company.tld",
    client_id: "CLIENT_ID",
    client_secret: "CLIENT_SECRET",
    redirect_uri: "https://www.company.tld/auth/callback",
    response_type: "code id_token",
    routes: {
      // You can customize the routes used to handle the login flow
      // These values are the default ones
      login: "/auth",
      callback: "/auth/callback",
    },
  })
);

// After a success login, this handler will be called, here you can redirect the
// user somewhere else
app.get("/auth/callback", (ctx) => {
  return ctx.redirect("/profile");
});

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

You can also access the Issuer and Client instances with:

```ts
app.get("/route", async (ctx) => {
  let issuer = oidc.issuer(ctx);
  let client = oidc.client(ctx);
  // do something with them
});
```

## Author

- [Sergio Xalambrí](https://sergiodxa.com)
