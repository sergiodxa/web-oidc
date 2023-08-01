export class OIDCError extends Error {
	cause?: Error;

	code: string;
	description: string | null;
	uri: string | null;

	constructor(
		code: string,
		{
			description,
			uri,
		}: {
			description: string | null;
			uri: string | null;
		},
	) {
		let message = code;
		if (description) message += `: ${description}`;
		if (uri) message += ` (${uri})`;

		super(message);

		this.code = code;
		this.description = description;
		this.uri = uri;
	}
}
