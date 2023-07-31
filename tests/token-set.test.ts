import { describe, expect, test } from "vitest";
import { TokenSet } from "../src/token-set";

describe(TokenSet.name, () => {
	test("returns claims from id_token", () => {
		let tokens = new TokenSet({
			access_token: "",
			token_type: "Bearer",
			refresh_token: "",
			expires_in: 86400,
			scope: ["openid", "profile", "offline_access"].join(" "),
			id_token:
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		});

		expect(tokens.claims()).toEqual({
			sub: "1234567890",
			name: "John Doe",
			iat: 1516239022,
		});
	});
});
