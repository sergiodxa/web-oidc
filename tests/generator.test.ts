import { describe, expect, test } from "vitest";

import { Generator } from "../src/generator";

describe(Generator.name, () => {
	test("generates a random state", () => {
		let state = Generator.state();
		expect(state).toStrictEqual(expect.any(String));
	});

	test("generates a random nonce", () => {
		let nonce = Generator.nonce();
		expect(nonce).toStrictEqual(expect.any(String));
	});

	test("generates a random code verifier", () => {
		let codeVerifier = Generator.codeVerifier();

		expect(codeVerifier).toStrictEqual(expect.any(String));
		expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
		expect(codeVerifier.length).toBeLessThanOrEqual(128);
	});

	test("generates a code challenge from a code verifier", () => {
		let codeVerifier = "code-verifier";

		let codeChallenge = Generator.codeChallenge(codeVerifier);

		expect(codeChallenge).toBe("qdgLLRr1saFHT6DWfWU28VNPIi7e9ynEBnBG3Oadw9g");
	});
});
