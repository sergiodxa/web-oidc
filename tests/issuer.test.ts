import { describe, expect, test } from "vitest";
import { Issuer } from "../src/issuer";

describe(Issuer.name, () => {
  test("fetches issuer metadata from accounts.google.com", async () => {
    let issuer = await Issuer.discover("https://accounts.google.com");
    expect(issuer.metadata).toEqual({
      claim_types_supported: ["normal"],
      claims_parameter_supported: false,
      grant_types_supported: [
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
      ],
      request_parameter_supported: false,
      request_uri_parameter_supported: true,
      require_request_uri_registration: false,
      response_modes_supported: ["query", "fragment"],
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
      issuer: "https://accounts.google.com",
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
      device_authorization_endpoint:
        "https://oauth2.googleapis.com/device/code",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
      revocation_endpoint: "https://oauth2.googleapis.com/revoke",
      scopes_supported: ["openid", "email", "profile"],
      response_types_supported: [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
        "none",
      ],
      code_challenge_methods_supported: ["plain", "S256"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      claims_supported: [
        "aud",
        "email",
        "email_verified",
        "exp",
        "family_name",
        "given_name",
        "iat",
        "iss",
        "locale",
        "name",
        "picture",
        "sub",
      ],
    });
  });

  test("fetches issuer metadata from auth0.com", async () => {
    let issuer = await Issuer.discover(
      "https://auth.auth0.com/.well-known/openid-configuration"
    );
    expect(issuer.metadata).toEqual({
      claim_types_supported: ["normal"],
      claims_parameter_supported: false,
      grant_types_supported: ["authorization_code", "implicit"],
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
      require_request_uri_registration: false,
      response_modes_supported: ["query", "fragment", "form_post"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
      ],
      issuer: "https://auth.auth0.com/",
      authorization_endpoint: "https://auth.auth0.com/authorize",
      token_endpoint: "https://auth.auth0.com/oauth/token",
      device_authorization_endpoint: "https://auth.auth0.com/oauth/device/code",
      userinfo_endpoint: "https://auth.auth0.com/userinfo",
      mfa_challenge_endpoint: "https://auth.auth0.com/mfa/challenge",
      jwks_uri: "https://auth.auth0.com/.well-known/jwks.json",
      registration_endpoint: "https://auth.auth0.com/oidc/register",
      revocation_endpoint: "https://auth.auth0.com/oauth/revoke",
      scopes_supported: [
        "openid",
        "profile",
        "offline_access",
        "name",
        "given_name",
        "family_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
        "created_at",
        "identities",
        "phone",
        "address",
      ],
      response_types_supported: [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
      ],
      code_challenge_methods_supported: ["S256", "plain"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["HS256", "RS256"],
      claims_supported: [
        "aud",
        "auth_time",
        "created_at",
        "email",
        "email_verified",
        "exp",
        "family_name",
        "given_name",
        "iat",
        "identities",
        "iss",
        "name",
        "nickname",
        "phone_number",
        "picture",
        "sub",
      ],
      token_endpoint_auth_signing_alg_values_supported: [
        "RS256",
        "RS384",
        "PS256",
      ],
    });
  });

  test("manually instantiates an issuer", () => {
    let issuer = new Issuer({
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
      issuer: "https://auth.company.tld",
      authorization_endpoint: "https://auth.company.tld/o/oauth2/v2/auth",
      token_endpoint: "https://auth0.company.tld/token",
      device_authorization_endpoint: "https://auth0.company.tld/device/code",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks_uri: "https://auth.company.tld/oauth2/v3/certs",
      revocation_endpoint: "https://auth0.company.tld/revoke",
      scopes_supported: ["openid", "email", "profile"],
      response_types_supported: [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
        "none",
      ],
      code_challenge_methods_supported: ["plain", "S256"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });

    expect(issuer.metadata).toEqual({
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
      issuer: "https://auth.company.tld",
      authorization_endpoint: "https://auth.company.tld/o/oauth2/v2/auth",
      token_endpoint: "https://auth0.company.tld/token",
      device_authorization_endpoint: "https://auth0.company.tld/device/code",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks_uri: "https://auth.company.tld/oauth2/v3/certs",
      revocation_endpoint: "https://auth0.company.tld/revoke",
      scopes_supported: ["openid", "email", "profile"],
      response_types_supported: [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
        "none",
      ],
      code_challenge_methods_supported: ["plain", "S256"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });
  });
});
