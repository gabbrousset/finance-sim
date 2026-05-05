// Community-maintained AAGUID list: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
const KNOWN: Record<string, string> = {
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '00000000-0000-0000-0000-000000000000': 'Passkey',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain'
};

export function suggestDeviceName(aaguid: string): string {
  return KNOWN[aaguid] ?? 'Passkey';
}
