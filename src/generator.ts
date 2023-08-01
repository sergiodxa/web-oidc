import { toByteArray, fromByteArray } from "base64-js";

export class Generator {
	static state() {
		return Generator.random();
	}

	static codeVerifier() {
		return this.random(128);
	}

	static async codeChallenge(codeVerifier: string) {
		let buffer = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(codeVerifier),
		);

		return fromByteArray(new Uint8Array(buffer))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=/g, "");
	}

	private static random(bytes = 32) {
		let result: string[] = [];

		for (let value of crypto.getRandomValues(new Uint8Array(bytes))) {
			result.push(value.toString(16).padStart(2, "0"));
		}

		return result.join("");
	}
}
