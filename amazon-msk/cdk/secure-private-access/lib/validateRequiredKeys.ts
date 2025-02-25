export function validateRequiredKeys(json: object, keys: string[]): void {
  const missingKeys = [];
  if (json !== null) {
    missingKeys.push(...keys.filter((key) => !(key in json)));
  }
  if (missingKeys.length > 0) {
    throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
  }
}
