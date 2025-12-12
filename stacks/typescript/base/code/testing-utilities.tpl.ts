/*
File: testing-utilities.tpl.ts
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
*/

export function assertContains(haystack: string, needle: string): void {
  expect(haystack).toContain(needle);
}
