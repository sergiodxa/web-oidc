import cryptoJS from "crypto-js";

export class Generator {
	static state() {
		return Generator.random();
	}

	static codeVerifier() {
		return Generator.random(96);
	}

	static codeChallenge(codeVerifier: string) {
		return cryptoJS.SHA256(codeVerifier).toString(cryptoJS.enc.Base64url);
	}

	private static random(bytes = 32) {
		return cryptoJS.lib.WordArray.random(bytes).toString(
			cryptoJS.enc.Base64url,
		);
	}
}
