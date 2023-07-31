import { describe, expect, test } from "vitest";

import { Generator } from "../src/generator";

describe(Generator.name, () => {
	test("generates a random state", () => {
		let state = Generator.state();
		expect(state).toStrictEqual(expect.any(String));
	});

	test("generates a random code verifier", () => {
		let codeVerifier = Generator.codeVerifier();
		expect(codeVerifier).toStrictEqual(expect.any(String));
	});

	test("generates a code challenge from a code verifier", async () => {
		let codeVerifier = "code-verifier";

		let codeChallenge = await Generator.codeChallenge(codeVerifier);

		expect(codeChallenge).toBe(
			"YTlkODBiMmQxYWY1YjFhMTQ3NGZhMGQ2N2Q2NTM2ZjE1MzRmMjIyZWRlZjcyOWM0MDY3MDQ2ZGNlNjlkYzNkOA",
		);
	});
});
