/* MIT License

Copyright (c) 2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

import { describe, it, expect, vi } from 'vitest';
import type { VerifiedUserItem } from '../src/models';

// Lookup counts are not observable against real DynamoDB, so the store is stubbed
const authsGo = vi.fn();
const aaguidsGo = vi.fn();
vi.mock('../src/models', () => ({
   Authenticators: { query: { byUserId: () => ({ go: authsGo }) } },
   AAGUIDs: { get: () => ({ go: aaguidsGo }) },
}));

import { loadAuthenticators, lightFileDefault, darkFileDefault } from '../src/server';

describe('authenticator details', () => {
   it('looks up listed and unlisted AAGUIDs only once', async () => {
      authsGo.mockResolvedValue({
         data: [
            { credentialId: 'cred1', description: 'listed', aaguid: 'listed-aaguid', createdAt: 1 },
            { credentialId: 'cred2', description: 'unlisted', aaguid: 'unlisted-aaguid', createdAt: 2 },
         ],
      });
      aaguidsGo.mockResolvedValue({
         data: [{ aaguid: 'listed-aaguid', name: 'Listed Key', lightIcon: 'light.svg', darkIcon: 'dark.svg' }],
      });
      const user = { userId: 'user1' } as VerifiedUserItem;

      const first = await loadAuthenticators(user);
      expect(first).toEqual([
         {
            credentialId: 'cred1',
            description: 'listed',
            name: 'Listed Key',
            lightIcon: 'light.svg',
            darkIcon: 'dark.svg',
         },
         {
            credentialId: 'cred2',
            description: 'unlisted',
            name: 'Passkey',
            lightIcon: lightFileDefault,
            darkIcon: darkFileDefault,
         },
      ]);

      const second = await loadAuthenticators(user);
      expect(second).toEqual(first);
      expect(aaguidsGo).toHaveBeenCalledTimes(1);
   });
});
