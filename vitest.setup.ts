import { afterAll, beforeAll, beforeEach } from "vitest";
import { server } from "./tests/mocks/server";
import "dotenv/config";

beforeAll(() => {
	server.listen({ onUnhandledRequest: "bypass" });
});

beforeEach(() => {
	server.resetHandlers();
});

afterAll(() => {
	server.close();
});
