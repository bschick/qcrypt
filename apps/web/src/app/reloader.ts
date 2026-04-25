/* MIT License

Copyright (c) 2025 Brad Schick

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

// Safety net for the edge case where a browser session outlives a chunk's
// retention on the CDN: if a lazy `import()` or lazy route load fails because
// the chunk was deleted by the deploy script's orphan-expiration logic, force
// a page reload so the app picks up the fresh build instead of white-screening.
//
// Works by wrapping the import call itself — we treat any rejection as a
// chunk-load failure without inspecting the error's message, so this stays
// robust across browsers, locales, and future error-phrasing changes.
//
// Every `import()` we care to guard must be passed through `guardedImport`.


// The import can fail for many reasons, including a deploy mid-flight
// or network flake. Only allow one reload per minute.
const RELOAD_GUARD_KEY = 'qcrypt-reload-at';
const RELOAD_GUARD_WINDOW_MS = 60000;


// Used to wrap dynamic imports. If the returned promise rejects for any
// reason, schedule a reload and re-throw so the caller's error pipeline
// still sees it.
export function guardedImport<T>(factory: () => Promise<T>): Promise<T> {
   return factory().catch((err) => {
      triggerReload(err);
      throw err;
   });
}

function triggerReload(reason: unknown): void {
   if (navigator.onLine === false) {
      console.warn('load error while offline, not reloading', reason);
      return;
   }
   const last = Number(sessionStorage.getItem(RELOAD_GUARD_KEY) ?? 0);
   if (Number.isFinite(last) && Date.now() - last < RELOAD_GUARD_WINDOW_MS) {
      console.error('reload guard tripped, not reloading again', reason);
      return;
   }
   console.warn('load failure, reloading to pick up fresh build', reason);
   sessionStorage.setItem(RELOAD_GUARD_KEY, String(Date.now()));
   window.location.reload();
}
