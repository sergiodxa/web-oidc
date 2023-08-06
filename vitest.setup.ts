import { afterAll, beforeAll, beforeEach } from "vitest";
import { server } from "./tests/mocks/server";

beforeAll(() => {
	server.listen({ onUnhandledRequest: "bypass" });
});

beforeEach(() => {
	server.resetHandlers();
});

afterAll(() => {
	server.close();
});
