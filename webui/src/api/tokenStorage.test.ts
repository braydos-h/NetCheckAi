// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";

import { clearStoredToken, getStoredToken, setStoredToken } from "@/api/client";

beforeEach(() => {
  clearStoredToken();
  sessionStorage.clear();
  localStorage.clear();
});

describe("bearer token storage (XSS hardening)", () => {
  it("never persists the token to sessionStorage or localStorage", () => {
    setStoredToken("super-secret-bearer");
    expect(getStoredToken()).toBe("super-secret-bearer");
    const sessionDump = JSON.stringify({ ...sessionStorage });
    const localDump = JSON.stringify({ ...localStorage });
    expect(sessionStorage.getItem("breachpilot.apiToken.v1")).toBeNull();
    expect(sessionDump).not.toContain("super-secret-bearer");
    expect(localDump).not.toContain("super-secret-bearer");
  });

  it("clearStoredToken drops the in-memory token", () => {
    setStoredToken("super-secret-bearer");
    clearStoredToken();
    expect(getStoredToken()).toBe("");
  });
});
