import { beforeAll, describe, expect, test } from "vitest";
import { server } from "./mocks/server";
import { rest } from "msw";
import { Client, Issuer, Generator, OIDCError } from "../src";
import { beforeEach } from "node:test";

describe(Client.name, () => {
	let state = Generator.state();
	let code_verifier = Generator.codeVerifier();

	let client: Client;

	beforeAll(async () => {
		server.use(
			rest.get(
				"https://auth.company.tld/.well-known/openid-configuration",
				async (_, res, ctx) => {
					return res(
						ctx.json({
							issuer: "https://auth.company.tld/",
							authorization_endpoint: "https://auth.company.tld/authorize",
							token_endpoint: "https://auth.company.tld/oauth/token",
							userinfo_endpoint: "https://auth.company.tld/userinfo",
						}),
					);
				},
			),
		);

		let issuer = await Issuer.discover("https://auth.company.tld");
		client = issuer.client({
			client_id: "CLIENT_ID",
			client_secret: "CLIENT_SECRET",
			redirect_uri: "https://company.tld/auth/callback",
			response_type: "code",
		});
	});

	test("fails with missing state check", async () => {
		let url = new URL("https://company.tld/auth/callback");
		url.searchParams.set("state", state);
		url.searchParams.set("code", "CODE");

		let request = new Request(url.toString());

		await expect(async () =>
			client.oauthCallback(
				new URL("https://company.tld/auth/callback"),
				await client.callbackParams(request.url),
				{ response_type: "code", code_verifier },
			),
		).rejects.toThrowError(
			new TypeError("Missing Client#oauthCallback checks.state"),
		);
	});

	test("fails with missing state on URL", async () => {
		let url = new URL("https://company.tld/auth/callback");
		url.searchParams.set("code", "CODE");

		let request = new Request(url.toString());

		await expect(async () =>
			client.oauthCallback(
				new URL("https://company.tld/auth/callback"),
				await client.callbackParams(request.url),
				{ response_type: "code", state, code_verifier },
			),
		).rejects.toThrowError(new ReferenceError("Missing state on URL."));
	});

	test("fails with state mismatch", async () => {
		let url = new URL("https://company.tld/auth/callback");
		url.searchParams.set("state", "WRONG_STATE");
		url.searchParams.set("code", "CODE");

		let request = new Request(url.toString());

		await expect(async () =>
			client.oauthCallback(
				new URL("https://company.tld/auth/callback"),
				await client.callbackParams(request.url),
				{ response_type: "code", state, code_verifier },
			),
		).rejects.toThrowError(new ReferenceError("State mismatch."));
	});

	test("fails with OIDCError", async () => {
		let url = new URL("https://company.tld/auth/callback");
		url.searchParams.set("state", state);
		url.searchParams.set("error", "invalid_request");
		url.searchParams.set("error_description", "This was a test error.");

		let request = new Request(url.toString());

		await expect(async () =>
			client.oauthCallback(
				new URL("https://company.tld/auth/callback"),
				await client.callbackParams(request.url),
				{ response_type: "code", state, code_verifier },
			),
		).rejects.toThrowError(
			new OIDCError("invalid_request", {
				description: "This was a test error.",
				uri: null,
			}),
		);
	});
});
