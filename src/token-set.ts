import { z } from "zod";
import { decodeJwt } from "jose";

export class TokenSet {
	public access_token!: string;
	public expires_in!: number;
	public id_token: string | undefined;
	public refresh_token: string | undefined;
	public scope!: string[];
	public token_type!: string;
	[key: string]: TokenSetValue[keyof TokenSetValue];

	constructor(values: TokenSetValue) {
		let result = TokenSetValueSchema.safeParse(values);

		if (!result.success) {
			throw new Error("Invalid argument for TokenSet", { cause: result.error });
		}

		Object.assign(this, result.data);
		const { constructor, ...properties } = Object.getOwnPropertyDescriptors(
			this.constructor.prototype,
		);

		Object.defineProperties(this, properties);
	}

	expired(token = this.access_token) {
		let { exp } = decodeJwt(token);
		if (!exp) return false;
		let now = Date.now() / 1000;
		return exp < now;
	}

	claims() {
		if (!this.id_token) throw new TypeError("id_token not present in TokenSet");
		return decodeJwt(this.id_token);
	}

	toJSON() {
		return {
			access_token: this.access_token,
			expires_in: this.expires_in,
			id_token: this.id_token,
			refresh_token: this.refresh_token,
			scope: this.scope.join(" "),
			token_type: this.token_type,
		};
	}

	toString() {
		return JSON.stringify(this);
	}
}

export const TokenSetValueSchema = z
	.object({
		access_token: z.string(),
		expires_in: z.number(),
		id_token: z.string().optional(),
		scope: z.string(),
		token_type: z
			.enum(["Bearer", "bearer"])
			.transform((value) => {
				let [first, ...rest] = value.split("");
				return [first.toUpperCase(), ...rest].join("");
			})
			.refine((value) => Object.is(value, "Bearer")),
		refresh_token: z.string().optional(),
	})
	.passthrough();

export type TokenSetValue = z.output<typeof TokenSetValueSchema>;
