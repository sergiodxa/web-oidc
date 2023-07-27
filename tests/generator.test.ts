import { describe, expect, test } from "vitest";

import { Generator } from "../src/generator";
import { z } from "zod";

describe(Generator.name, () => {
  test("generates a random uuid", () => {
    let state = Generator.state();
    expect(state).toStrictEqual(expect.any(String));
  });
});
