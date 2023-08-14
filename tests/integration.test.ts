import { describe, expect, test } from "vitest";

import { Client, Issuer, Generator, TokenSet } from "../src";
import { server } from "./mocks/server";
import { rest } from "msw";
import { z } from "zod";

describe("Integration tests", () => {
	describe("Auth0", () => {
		let issuer: Issuer;
		let client: Client;

		test("creates Issuer", async () => {
			server.use(
				rest.get(
					"https://auth.auth0.com/.well-known/openid-configuration",
					async (_, res, ctx) => {
						return res(
							ctx.json({
								issuer: "https://auth.auth0.com/",
								authorization_endpoint: "https://auth.auth0.com/authorize",
								token_endpoint: "https://auth.auth0.com/oauth/token",
								userinfo_endpoint: "https://auth.auth0.com/userinfo",
							}),
						);
					},
				),
			);

			issuer = await Issuer.discover("https://auth.auth0.com");

			expect(issuer.metadata).toEqual({
				claim_types_supported: ["normal"],
				claims_parameter_supported: false,
				grant_types_supported: ["authorization_code", "implicit"],
				request_parameter_supported: false,
				request_uri_parameter_supported: true,
				require_request_uri_registration: false,
				response_modes_supported: ["query", "fragment"],
				token_endpoint_auth_methods_supported: ["client_secret_basic"],
				issuer: "https://auth.auth0.com/",
				authorization_endpoint: "https://auth.auth0.com/authorize",
				token_endpoint: "https://auth.auth0.com/oauth/token",
				userinfo_endpoint: "https://auth.auth0.com/userinfo",
			});
		});

		test("creates Client from Issuer", () => {
			client = issuer.client({
				client_id: "CLIENT_ID",
				client_secret: "CLIENT_SECRET",
				redirect_uri: "https://company.tld/auth/callback",
				response_type: "code",
			});

			expect(client).toBeInstanceOf(Client);
		});

		test("creates an authorization URL", () => {
			let state = Generator.state();
			let code_challenge = Generator.codeChallenge(Generator.codeVerifier());

			let url = client.authorizationUrl({
				redirect_uri: "https://company.tld/auth/callback",
				state,
				code_challenge,
				code_challenge_method: "S256",
				response_type: "code",
				scope: ["openid", "email"],
			});

			expect(url.toString()).toBe(
				`https://auth.auth0.com/authorize?response_type=code&client_id=CLIENT_ID&scope=openid+email&redirect_uri=https%3A%2F%2Fcompany.tld%2Fauth%2Fcallback&state=${state}&code_challenge=${code_challenge}&code_challenge_method=S256`,
			);
		});

		test("handles OAuth2 callback", async () => {
			let state = Generator.state();
			let code_verifier = Generator.codeVerifier();

			server.use(
				rest.post(
					"https://auth.auth0.com/oauth/token",
					async (req, res, ctx) => {
						let body = await req.text();
						let params = new URLSearchParams(body);

						expect(params.get("grant_type")).toBe("authorization_code");
						expect(params.get("code")).toBe("CODE");
						expect(params.get("redirect_uri")).toBe(
							"https://company.tld/auth/callback",
						);
						expect(params.get("code_verifier")).toBe(code_verifier);
						expect(params.get("client_id")).toBe("CLIENT_ID");
						expect(params.get("client_secret")).toBe("CLIENT_SECRET");

						return res(
							ctx.json({
								access_token: "ACCESS_TOKEN",
								expires_in: 86400,
								id_token: "ID_TOKEN",
								scope: "openid offline_access",
								token_type: "Bearer",
								refresh_token: "REFRESH_TOKEN",
							}),
						);
					},
				),
			);

			let url = new URL("https://company.tld/auth/callback");
			url.searchParams.set("state", state);
			url.searchParams.set("code", "CODE");

			let request = new Request(url.toString());

			let params = await client.callbackParams(request.url);

			let tokens = await client.oauthCallback(
				new URL("https://company.tld/auth/callback"),
				params,
				{ response_type: "code", state, code_verifier },
			);

			expect(tokens).toBeInstanceOf(TokenSet);
			expect(tokens.access_token).toBe("ACCESS_TOKEN");
			expect(tokens.id_token).toBe("ID_TOKEN");
			expect(tokens.refresh_token).toBe("REFRESH_TOKEN");
		});

		test("fetches current user profile", async () => {
			let sub = crypto.randomUUID();

			server.use(
				rest.get("https://auth.auth0.com/userinfo", async (req, res, ctx) => {
					expect(req.headers.get("authorization")).toBe("Bearer ACCESS_TOKEN");

					return res(ctx.json({ sub }));
				}),
			);

			await expect(client.userinfo("ACCESS_TOKEN")).resolves.toEqual({ sub });
		});

		test("refreshes access token", async () => {
			server.use(
				rest.post(
					"https://auth.auth0.com/oauth/token",
					async (req, res, ctx) => {
						let body = await req.text();
						let params = new URLSearchParams(body);

						expect(params.get("grant_type")).toBe("refresh_token");
						expect(params.get("client_id")).toBe("CLIENT_ID");
						expect(params.get("client_secret")).toBe("CLIENT_SECRET");

						return res(
							ctx.json({
								access_token: "ACCESS_TOKEN",
								expires_in: 86400,
								id_token: "ID_TOKEN",
								scope: "openid offline_access",
								token_type: "Bearer",
								refresh_token: "REFRESH_TOKEN",
							}),
						);
					},
				),
			);

			let tokens = await client.refresh("ACCESS_TOKEN");

			expect(tokens).toBeInstanceOf(TokenSet);
			expect(tokens.access_token).toBe("ACCESS_TOKEN");
			expect(tokens.id_token).toBe("ID_TOKEN");
			expect(tokens.refresh_token).toBe("REFRESH_TOKEN");
		});
	});

	describe("GitHub", () => {
		let env = z
			.object({ GH_CLIENT_ID: z.string(), GH_CLIENT_SECRET: z.string() })
			.parse(process.env);

		let redirectUri = "http://localhost:3000/auth/github/callback";

		let issuer: Issuer;
		let client: Client;

		test("creates Issuer", () => {
			issuer = new Issuer({
				issuer: "https://github.com",
				userinfo_endpoint: "https://api.github.com/user",
				authorization_endpoint: "https://github.com/login/oauth/authorize",
				token_endpoint: "https://github.com/login/oauth/access_token",
				device_authorization_endpoint: "https://github.com/login/device/code",
			});

			expect(issuer).toBeInstanceOf(Issuer);
			expect(issuer.metadata).toEqual({
				issuer: "https://github.com",
				userinfo_endpoint: "https://api.github.com/user",
				authorization_endpoint: "https://github.com/login/oauth/authorize",
				token_endpoint: "https://github.com/login/oauth/access_token",
				device_authorization_endpoint: "https://github.com/login/device/code",
			});
		});

		test("creates Client from Issuer", () => {
			client = issuer.client({
				client_id: env.GH_CLIENT_ID,
				client_secret: env.GH_CLIENT_SECRET,
				redirect_uri: redirectUri,
				response_type: "code",
			});

			expect(client).toBeInstanceOf(Client);
		});

		test("creates an authorization URL", () => {
			let state = Generator.state();
			let code_challenge = Generator.codeChallenge(Generator.codeVerifier());

			let url = client.authorizationUrl({
				redirect_uri: redirectUri,
				state,
				code_challenge,
				code_challenge_method: "S256",
				response_type: "code",
				scope: "openid email",
			});

			expect(url.toString()).toBe(
				`https://github.com/login/oauth/authorize?response_type=code&client_id=${env.GH_CLIENT_ID}&scope=openid+email&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fgithub%2Fcallback&state=${state}&code_challenge=${code_challenge}&code_challenge_method=S256`,
			);
		});

		test("handles OAuth2 callback", async () => {
			let state = Generator.state();
			let code_verifier = Generator.codeVerifier();

			server.use(
				rest.post(
					"https://github.com/login/oauth/access_token",
					async (req, res, ctx) => {
						let body = await req.text();
						let params = new URLSearchParams(body);

						expect(params.get("grant_type")).toBe("authorization_code");
						expect(params.get("code")).toBe("CODE");
						expect(params.get("redirect_uri")).toBe(redirectUri);
						expect(params.get("code_verifier")).toBe(code_verifier);
						expect(params.get("client_id")).toBe(env.GH_CLIENT_ID);
						expect(params.get("client_secret")).toBe(env.GH_CLIENT_SECRET);

						return res(
							ctx.json({
								access_token: "gho_16C7e42F292c6912E7710c838347Ae178B4a",
								scope: "repo,gist",
								token_type: "bearer",
							}),
						);
					},
				),
			);

			let url = new URL(redirectUri);
			url.searchParams.set("state", state);
			url.searchParams.set("code", "CODE");

			let request = new Request(url.toString());

			let params = await client.callbackParams(request.url);

			let tokens = await client.oauthCallback(new URL(redirectUri), params, {
				response_type: "code",
				state,
				code_verifier,
			});

			expect(tokens).toBeInstanceOf(TokenSet);
			expect(tokens.access_token).toBe(
				"gho_16C7e42F292c6912E7710c838347Ae178B4a",
			);
			expect(tokens.scope).toBe("repo,gist");
			expect(tokens.token_type).toBe("Bearer");
		});

		test.todo("fetches current user profile");

		test.todo("refreshes access token");
	});
});
