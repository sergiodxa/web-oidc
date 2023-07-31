import { Context, type MiddlewareHandler } from "hono";
import { setCookie, getCookie } from "hono/cookie";

import type { ClientOptions, Client, UserInfo } from "./client";
import { Issuer } from "./issuer";
import { TokenSetValue } from "./token-set";
import { Generator } from "./generator";

interface OIDCMiddlewareOptions extends ClientOptions {
	issuer: Issuer | string | URL;
	routes?: { login: `/${string}`; callback: `/${string}` };
	cookies: { session?: `oidc:${string}`; state?: `oidc:${string}` };
}

const OptionsSymbol = Symbol();
const IssuerSymbol = Symbol();
const ClientSymbol = Symbol();
const UserInfoSymbol = Symbol();

export function oidc({
	issuer,
	routes = { login: "/auth", callback: "/auth/callback" },
	cookies = { session: "oidc:session", state: "oidc:state" },
	...options
}: OIDCMiddlewareOptions): MiddlewareHandler {
	return async function middleware(context, next) {
		if (issuer instanceof Issuer) {
		} else {
			issuer = await Issuer.discover(issuer);
		}

		let client = issuer.client(options);

		let url = new URL(context.req.url);

		if (
			(url.pathname === routes.login ?? "/login") &&
			context.req.method.toUpperCase() === "POST"
		) {
			let state = Generator.state();

			setCookie(context, cookies.state ?? "oidc:state", state, {
				path: "/",
				httpOnly: true,
				maxAge: 60 * 60 * 24 * 7,
			});

			return context.redirect(client.authorizationUrl({ state }).toString());
		}

		if (
			(url.pathname === routes.callback ?? "/callback") &&
			context.req.method.toUpperCase() === "GET"
		) {
			let params = await client.callbackParams(url);

			let tokens = await client.oauthCallback(
				new URL(options.redirect_uri),
				params,
				{
					response_type: options.response_type,
					state: getCookie(context, cookies.state ?? "oidc:state"),
				},
			);

			setCookie(context, cookies.session ?? "oidc:session", tokens.toString());
		}

		context.set(IssuerSymbol, issuer);
		context.set(ClientSymbol, client);
		context.set(OptionsSymbol, { routes, cookies });

		return await next();
	};
}

oidc.isAuthenticated = function isAuthenticated(context: Context) {
	let session = getCookie(context, "oidc:session");
	return session !== undefined;
};

interface OIDCAuthenticateOptions {
	failureRedirect: `/${string}`;
	successRedirect: `/${string}`;
}

oidc.authenticate = function authenticate(
	options: OIDCAuthenticateOptions,
): MiddlewareHandler {
	return async function middleware(context, next) {
		let isAuthenticated = oidc.isAuthenticated(context);
		let { routes } = context.get(OptionsSymbol) as Pick<
			OIDCMiddlewareOptions,
			"cookies" | "routes"
		>;

		switch (true) {
			case !isAuthenticated && Boolean(options.failureRedirect): {
				return context.redirect(options.failureRedirect);
			}

			case isAuthenticated && Boolean(options.successRedirect): {
				return context.redirect(options.successRedirect);
			}

			case isAuthenticated && !Boolean(options.successRedirect): {
				context.set(UserInfoSymbol, await oidc.user(context));
			}

			case !isAuthenticated && !Boolean(options.failureRedirect): {
				return context.redirect(routes?.login ?? "/oauth");
			}
		}

		return await next();
	};
};

oidc.user = async function user(context: Context) {
	let user = context.get(UserInfoSymbol) as UserInfo | undefined;
	if (user) return user;

	let client = context.get(ClientSymbol) as Client;

	let { cookies } = context.get(OptionsSymbol) as Pick<
		OIDCMiddlewareOptions,
		"cookies" | "routes"
	>;

	let { access_token } = getCookie(
		context,
		cookies.session ?? "oidc:session",
	) as unknown as TokenSetValue;

	return await client.userinfo(access_token);
};

oidc.issuer = function issuer(context: Context) {
	let issuer = context.get(IssuerSymbol) as Issuer | undefined;
	if (!issuer) {
		throw new ReferenceError(
			"oidc.issuer must be called after the oidc middleware runs",
		);
	}
	return issuer;
};

oidc.client = function client(context: Context) {
	let client = context.get(ClientSymbol) as Client | undefined;
	if (!client) {
		throw new ReferenceError(
			"oidc.client must be called after the oidc middleware runs",
		);
	}
	return client;
};
