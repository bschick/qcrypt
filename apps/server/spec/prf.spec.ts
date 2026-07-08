import { describe, it, expect } from 'vitest';
import { bytesToBase64 } from '@qcrypt/crypto';
import {
   registerPrfTestUser,
   postJson,
   prfDecrypt,
   readPrfOutput,
   PRF_EXTENSION,
   RP_ORIGIN,
} from './common';

describe('PRF account registration and login', () => {
   it('registers a PRF account and logs in, decrypting the per-passkey ciphertext back to userCred', async () => {
      const testUser = `PWTesty_prf_${Date.now()}`;
      const account = await registerPrfTestUser(testUser, 'hmac-secret-mc');

      // hmac-secret-mc returns the PRF output during registration, so no follow-up assertion ran
      expect(account.prfCase).toBe('create');

      const optsRes = await postJson('/v1/auth/options', { userId: account.userId }, {}, '');
      expect(optsRes.status).toBe(200);

      const assertion = account.emulator.getJSON(RP_ORIGIN, {
         ...optsRes.data,
         challenge: optsRes.data.challenge,
         extensions: PRF_EXTENSION,
      });

      const verifyRes = await postJson(
         '/v1/auth/verify?usercred=true',
         { ...assertion, challenge: optsRes.data.challenge },
         {},
         ''
      );
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.prf).toBe(true);
      expect(verifyRes.data.userCred).toBeUndefined();
      expect(verifyRes.data.passkeyUserCredEnc).toBeDefined();

      // The login assertion reproduces the registration PRF output, so it decrypts the
      // server-stored per-passkey ciphertext back to the userCred the client generated.
      const prfOutput = readPrfOutput(assertion.clientExtensionResults);
      expect(prfOutput).not.toBeNull();
      const decrypted = await prfDecrypt(verifyRes.data.passkeyUserCredEnc, prfOutput!, account.userId);
      expect(bytesToBase64(decrypted)).toBe(account.userCred);
   });
});
