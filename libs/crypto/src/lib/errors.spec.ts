import { decryptionErrorMessage } from './errors';

describe('decryptionErrorMessage', () => {
   it('returns undefined for unknown errors', () => {
      expect(decryptionErrorMessage(new Error('Cipher armor text not formatted correctly'), 'passkey')).toBeUndefined();
      expect(decryptionErrorMessage('not an error', 'passkey')).toBeUndefined();
   });
});
