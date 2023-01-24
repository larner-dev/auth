import { index } from "./index";

console.log("a");

describe("index", () => {
  test("it should equal foo", () => {
    expect(index).toEqual("foo");
  });
});

console.log("b");
