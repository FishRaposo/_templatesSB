/*
File: testing-utilities.tpl.ts
Purpose: Comprehensive testing utilities for Jest/Vitest
Generated for: {{PROJECT_NAME}}
*/

/**
 * Mocks the global fetch API for testing
 * @param responseBody The JSON body to return
 * @param status HTTP status code (default 200)
 */
export function mockFetchResponse(responseBody: any, status: number = 200) {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(responseBody),
    } as Response)
  );
}

/**
 * Resets the fetch mock
 */
export function resetFetchMock() {
  (global.fetch as jest.Mock).mockClear();
}

/**
 * Helper to generate a dummy JWT token for auth testing
 */
export function generateTestToken(payload: object = { sub: "test-user" }): string {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64");
    return `${header}.${body}.signature_placeholder`;
}

/**
 * Custom matcher for partial object matching
 */
export const matchPartial = (expected: object) => expect.objectContaining(expected);

/**
 * Assert that a promise rejects with a specific error message
 */
export async function assertRejectsWith(promise: Promise<any>, errorMessage: string) {
    await expect(promise).rejects.toThrow(errorMessage);
}
