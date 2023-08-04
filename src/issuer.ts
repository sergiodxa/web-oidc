import { z } from "zod";
import { Client, ClientOptions } from "./client";

const ISSUER_DEFAULTS: Partial<Metadata> = {
	claim_types_supported: ["normal"],
	claims_parameter_supported: false,
	grant_types_supported: ["authorization_code", "implicit"],
	request_parameter_supported: false,
	request_uri_parameter_supported: true,
	require_request_uri_registration: false,
	response_modes_supported: ["query", "fragment"],
	token_endpoint_auth_methods_supported: ["client_secret_basic"],
};

/**
 * @example
 * import { Issuer } from "web-oidc";
 * let issuer = await Issuer.discover("https://auth.company.tld");
 * @example
 * import { Issuer } from "web-oidc";
 * let issuer = new Issuer(metadata);
 */
export class Issuer {
	private config: Metadata;

	constructor(config: Metadata) {
		let result = MetadataSchema.safeParse(config);
		if (result.success) this.config = result.data;
		else throw new Error("Invalid issuer metadata", { cause: result.error });
	}

	get metadata() {
		return Object.freeze(structuredClone(this.config));
	}

	client(options: ClientOptions) {
		return new Client(this, options);
	}

	static async discover(uri: string | URL) {
		let url = new URL(uri);

		if (url.pathname.includes("/.well-known/")) {
			let response = await fetch(url, {
				method: "GET",
				headers: { accept: "application/json" },
			});

			let body = await MetadataSchema.promise().parse(response.json());

			return new Issuer({
				...ISSUER_DEFAULTS,
				...body,
			});
		}

		let pathname;
		if (url.pathname.endsWith("/")) {
			pathname = `${url.pathname}.well-known/openid-configuration`;
		} else {
			pathname = `${url.pathname}/.well-known/openid-configuration`;
		}

		let wellKnownUri = new URL(pathname, url);

		let response = await fetch(wellKnownUri, {
			method: "GET",
			headers: { accept: "application/json" },
		});

		let body = await MetadataSchema.promise().parse(response.json());

		return new Issuer({
			...ISSUER_DEFAULTS,
			...body,
		});
	}
}

export type ClientAuthMethod =
	| "client_secret_basic"
	| "client_secret_post"
	| "client_secret_jwt"
	| "private_key_jwt"
	| "tls_client_auth"
	| "self_signed_tls_client_auth"
	| "none";

const MetadataSchema = z
	.object({
		claim_types_supported: z.enum(["normal"]).array().optional(),
		claims_parameter_supported: z.boolean().optional(),
		grant_types_supported: z
			.enum([
				"authorization_code",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
				"urn:ietf:params:oauth:grant-type:jwt-bearer",
				"implicit",
			])
			.array()
			.optional(),
		request_parameter_supported: z.boolean().optional(),
		request_uri_parameter_supported: z.boolean().optional(),
		require_request_uri_registration: z.boolean().optional(),
		response_modes_supported: z
			.enum(["query", "fragment", "form_post"])
			.array()
			.optional(),
		token_endpoint_auth_methods_supported: z
			.enum([
				"client_secret_basic",
				"client_secret_post",
				"client_secret_jwt",
				"private_key_jwt",
				"tls_client_auth",
				"self_signed_tls_client_auth",
				"none",
			])
			.array()
			.optional(),
		issuer: z.string(),
		authorization_endpoint: z.string().url(),
		token_endpoint: z.string().url(),
		device_authorization_endpoint: z.string().url().optional(),
		userinfo_endpoint: z.string().url(),
		mfa_challenge_endpoint: z.string().url().optional(),
		jwks_uri: z.string().url().optional(),
		registration_endpoint: z.string().url().optional(),
		revocation_endpoint: z.string().url().optional(),
		scopes_supported: z
			.enum([
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
			])
			.array()
			.optional(),
		response_types_supported: z
			.enum([
				"code",
				"token",
				"id_token",
				"code token",
				"code id_token",
				"token id_token",
				"code token id_token",
				"none",
			])
			.array()
			.optional(),
		code_challenge_methods_supported: z
			.enum(["plain", "S256"])
			.array()
			.optional(),
		subject_types_supported: z.enum(["public"]).array().optional(),
		id_token_signing_alg_values_supported: z
			.enum(["HS256", "RS256"])
			.array()
			.optional(),
		claims_supported: z
			.enum([
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
				"locale",
			])
			.array()
			.optional(),
		token_endpoint_auth_signing_alg_values_supported: z
			.enum(["RS256", "RS384", "PS256"])
			.array()
			.optional(),
	})
	.passthrough();

export type Metadata = z.infer<typeof MetadataSchema>;
