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

