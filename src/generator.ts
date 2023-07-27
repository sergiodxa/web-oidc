export class Generator {
  static state() {
    let result: string[] = [];

    for (let value of crypto.getRandomValues(new Uint8Array(16))) {
      result.push(value.toString(16).padStart(2, "0"));
    }

    return result.join("");
  }
}
