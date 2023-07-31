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

		let hash = Array.from(new Uint8Array(buffer))
			.map((byte) => byte.toString(16).padStart(2, "0"))
			.join("");

		return Buffer.from(hash).toString("base64url");
	}

	private static random(bytes = 32) {
		let result: string[] = [];

		for (let value of crypto.getRandomValues(new Uint8Array(bytes))) {
			result.push(value.toString(16).padStart(2, "0"));
		}

		return result.join("");
	}
}
