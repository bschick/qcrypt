import { test, expect } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { HEAP_SCAN_TEST_OPTIONS, byteSecret, callInPage, scanHeap, textSecret, type Secret } from './heapscan';

test.use(HEAP_SCAN_TEST_OPTIONS);
// A shape the scan cannot reach fails the same way on every attempt
test.describe.configure({ retries: 0 });

// Each name is one way page code can hold bytes. Names ending in Large hold 128 bytes, which V8 stores
// outside the JS heap, while the 32-byte canaries are stored inside it.
const SHAPES = [
   'property',
   'largeBufferOffset',
   'subarray',
   'dataView',
   'bareArrayBuffer',
   'arrayElement',
   'mapValue',
   'mapKey',
   'setMember',
   'closureVariable',
   'timerCallback',
   'privateField',
   'privateFieldLarge',
   'weakMapValue',
   'weakMapValueLarge',
   'promiseResult',
   'promiseResultLarge',
   'nullPrototype',
   'nullPrototypeLarge',
   'domExpando',
   'eventListener',
   'symbolKey',
   'getterClosure',
   'uint32View',
   'asyncLocal',
   'byteValueArray',
   'wasmMemory',
];

// Closures created here retain this function's scope. Setting source to undefined at the end stops that scope
// from holding a second copy of each canary.
const PLANT_FN = `function (canaries, text) {
   let source = canaries;
   const make = (name) => new Uint8Array(source[name]);
   const holder = {};
   holder.property = make('property');
   const large = new Uint8Array(4096);
   large.set(source.largeBufferOffset, 1000);
   holder.largeBufferOffset = large;
   const base = new Uint8Array(256);
   base.set(source.subarray, 100);
   holder.subarray = base.subarray(100, 132);
   holder.dataView = new DataView(make('dataView').buffer);
   holder.bareArrayBuffer = make('bareArrayBuffer').buffer;
   holder.arrayElement = [0, 1, make('arrayElement')];
   holder.mapValue = new Map([['key', make('mapValue')]]);
   holder.mapKey = new Map([[make('mapKey'), 1]]);
   holder.setMember = new Set([make('setMember')]);
   holder.closureVariable = (() => {
      const key = make('closureVariable');
      return () => key.length;
   })();
   (() => {
      const key = make('timerCallback');
      setTimeout(() => key.length, 600000);
   })();
   class Holder {
      #key;
      constructor(key) {
         this.#key = key;
      }
      size() {
         return this.#key.length;
      }
   }
   holder.privateField = new Holder(make('privateField'));
   holder.privateFieldLarge = new Holder(make('privateFieldLarge'));
   const weakKey = {};
   const weakKeyLarge = {};
   holder.weakKeys = [weakKey, weakKeyLarge];
   holder.weakMap = new WeakMap([[weakKey, make('weakMapValue')], [weakKeyLarge, make('weakMapValueLarge')]]);
   holder.promiseResult = Promise.resolve(make('promiseResult'));
   holder.promiseResultLarge = Promise.resolve(make('promiseResultLarge'));
   const nullPrototype = Object.create(null);
   nullPrototype.key = make('nullPrototype');
   nullPrototype.large = make('nullPrototypeLarge');
   holder.nullPrototype = nullPrototype;
   document.body.__qcHeapScanExpando = make('domExpando');
   (() => {
      const key = make('eventListener');
      document.body.addEventListener('qc-heap-scan', () => key.length);
   })();
   holder.symbolKey = { [Symbol('key')]: make('symbolKey') };
   (() => {
      const key = make('getterClosure');
      Object.defineProperty(holder, 'getterClosure', { get: () => key });
   })();
   holder.uint32View = new Uint32Array(make('uint32View').buffer);
   holder.pending = new Promise(() => {});
   (async () => {
      const key = make('asyncLocal');
      await holder.pending;
      return key.length;
   })();
   holder.byteValueArray = Array.from(source.byteValueArray);
   const memory = new WebAssembly.Memory({ initial: 1 });
   new Uint8Array(memory.buffer).set(source.wasmMemory, 4096);
   holder.memory = memory;
   holder.text = text;
   globalThis.__qcHeapScanShapes = holder;
   const planted = Object.keys(source).length;
   source = undefined;
   return planted;
}`;

test('heap scan finds canaries in every holding shape', async ({ page }) => {
   await page.goto('/');
   await page.waitForLoadState('networkidle');

   const canaries: Record<string, number[]> = {};
   const secrets: Secret[] = [];
   for (const name of SHAPES) {
      const bytes = randomBytes(name.endsWith('Large') ? 128 : 32);
      canaries[name] = [...bytes];
      secrets.push(byteSecret(name, bytes, false));
   }
   const text = randomBytes(32).toString('base64url');
   secrets.push(textSecret('string', text));

   expect(await callInPage<number>(page, PLANT_FN, [canaries, text])).toBe(SHAPES.length);
   const scan = await scanHeap(page, 'canaries', secrets);

   for (const secret of secrets) {
      expect
         .soft(
            scan.findings.some((finding) => finding.secret === secret.name),
            `canary held as ${secret.name}`,
         )
         .toBe(true);
   }
   expect.soft(scan.unresolved, 'buffers the scan could not read').toEqual([]);
});
