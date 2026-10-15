import type { CDPSession, Page, PlaywrightWorkerOptions } from '@playwright/test';

// Playwright options that heap scans depend on
export const HEAP_SCAN_TEST_OPTIONS: Pick<PlaywrightWorkerOptions, 'launchOptions' | 'trace'> = {
   // Heap snapshots truncate strings at 1024 characters by default, which would hide a secret inside a longer string
   launchOptions: { args: ['--js-flags=--heap-snapshot-string-limit=100000000'] },
   // Playwright's trace recorder caches data on DOM nodes. Those caches retain detached elements and their text.
   trace: 'off',
};

export type Secret = {
   name: string;
   // [form, text] pairs searched in the heap snapshot's strings
   texts: [string, string][];
   // [form, bytes] pairs searched in ArrayBuffers, WebAssembly memories and arrays of byte values
   bytes: [string, number[]][];
};

export type Finding = {
   secret: string;
   form: string;
   kind: 'bytes' | 'string';
   location: string;
   retainers: string;
   // False when only DevTools protocol handles retain the copy, such as Playwright's handles to the
   // results of its page evaluations. Those handles do not exist outside of tests.
   reachable: boolean;
};

export type HeapScan = {
   label: string;
   findings: Finding[];
   // Buffers in the heap that the scan could neither reach nor read, each with its retainer path
   unresolved: string[];
   summary: string;
};

function uniqueForms<T>(forms: [string, T][]): [string, T][] {
   const seen = new Set<string>();
   return forms.filter(([, value]) => {
      const key = JSON.stringify(value);
      const isNew = !seen.has(key);
      seen.add(key);
      return isNew;
   });
}

// withText=false skips the encoded text forms, which are meaningless for a slice taken from a longer secret
export function byteSecret(name: string, value: Uint8Array, withText = true): Secret {
   const raw = Buffer.from(value);
   const texts = withText
      ? uniqueForms<string>([
           ['b64url', raw.toString('base64url')],
           ['b64', raw.toString('base64')],
           ['hex', raw.toString('hex')],
        ])
      : [];
   const textBytes = texts.map(([form, text]): [string, number[]] => [`${form}-ascii`, [...Buffer.from(text)]]);
   return { name, texts, bytes: uniqueForms<number[]>([['raw', [...raw]], ...textBytes]) };
}

export function textSecret(name: string, value: string): Secret {
   return {
      name,
      texts: [['text', value]],
      bytes: uniqueForms<number[]>([
         ['utf8', [...Buffer.from(value, 'utf8')]],
         ['utf16', [...Buffer.from(value, 'utf16le')]],
      ]),
   };
}

export function describeFinding(finding: Finding): string {
   return `${finding.secret}/${finding.form} in ${finding.location}, retained by: ${finding.retainers}`;
}

type HeapSnapshot = {
   snapshot: {
      meta: {
         node_fields: string[];
         node_types: [string[], ...unknown[]];
         edge_fields: string[];
         edge_types: [string[], ...unknown[]];
      };
   };
   nodes: number[];
   edges: number[];
   strings: string[];
};

type Retainer = { node: number; edge: number };

const NO_ROOT_PATH = '(no path from the GC roots)';

class HeapGraph {
   readonly nodeCount: number;
   private readonly _nodeFields: number;
   private readonly _edgeFields: number;
   private readonly _nodeType: number;
   private readonly _nodeName: number;
   private readonly _nodeId: number;
   private readonly _edgeType: number;
   private readonly _edgeName: number;
   private readonly _edgeTo: number;
   private readonly _nodeTypes: string[];
   private readonly _edgeTypes: string[];
   private readonly _firstEdge: Uint32Array;
   private readonly _retainerStart: Uint32Array;
   private readonly _retainerNode: Uint32Array;
   private readonly _retainerEdge: Uint32Array;
   private _ordinals: Map<number, number> | undefined;

   constructor(readonly snapshot: HeapSnapshot) {
      const meta = snapshot.snapshot.meta;
      this._nodeFields = meta.node_fields.length;
      this._edgeFields = meta.edge_fields.length;
      this._nodeType = meta.node_fields.indexOf('type');
      this._nodeName = meta.node_fields.indexOf('name');
      this._nodeId = meta.node_fields.indexOf('id');
      this._edgeType = meta.edge_fields.indexOf('type');
      this._edgeName = meta.edge_fields.indexOf('name_or_index');
      this._edgeTo = meta.edge_fields.indexOf('to_node');
      this._nodeTypes = meta.node_types[0];
      this._edgeTypes = meta.edge_types[0];
      this.nodeCount = snapshot.nodes.length / this._nodeFields;

      const edgeCountField = meta.node_fields.indexOf('edge_count');
      const weak = this._edgeTypes.indexOf('weak');
      const nodes = snapshot.nodes;
      const edges = snapshot.edges;

      // Weak references do not prevent garbage collection, so the retainer index omits them
      this._firstEdge = new Uint32Array(this.nodeCount + 1);
      const counts = new Uint32Array(this.nodeCount + 1);
      let edgePos = 0;
      for (let i = 0; i < this.nodeCount; i++) {
         this._firstEdge[i] = edgePos;
         const edgeCount = nodes[i * this._nodeFields + edgeCountField];
         for (let k = 0; k < edgeCount; k++, edgePos += this._edgeFields) {
            if (edges[edgePos + this._edgeType] !== weak) {
               counts[edges[edgePos + this._edgeTo] / this._nodeFields + 1]++;
            }
         }
      }
      this._firstEdge[this.nodeCount] = edgePos;
      for (let i = 0; i < this.nodeCount; i++) {
         counts[i + 1] += counts[i];
      }
      this._retainerStart = counts;
      const next = counts.slice(0, this.nodeCount);
      this._retainerNode = new Uint32Array(counts[this.nodeCount]);
      this._retainerEdge = new Uint32Array(counts[this.nodeCount]);
      for (let i = 0; i < this.nodeCount; i++) {
         for (let pos = this._firstEdge[i]; pos < this._firstEdge[i + 1]; pos += this._edgeFields) {
            if (edges[pos + this._edgeType] !== weak) {
               const target = edges[pos + this._edgeTo] / this._nodeFields;
               this._retainerNode[next[target]] = i;
               this._retainerEdge[next[target]] = pos;
               next[target]++;
            }
         }
      }
   }

   nodeId(ord: number): number {
      return this.snapshot.nodes[ord * this._nodeFields + this._nodeId];
   }

   nodeType(ord: number): string {
      return this._nodeTypes[this.snapshot.nodes[ord * this._nodeFields + this._nodeType]];
   }

   nodeName(ord: number): string {
      return this.snapshot.strings[this.snapshot.nodes[ord * this._nodeFields + this._nodeName]] ?? '';
   }

   nameIndex(ord: number): number {
      return this.snapshot.nodes[ord * this._nodeFields + this._nodeName];
   }

   edgeType(edge: number): string {
      return this._edgeTypes[this.snapshot.edges[edge + this._edgeType]];
   }

   // Element and hidden edges carry an index rather than a string table entry
   edgeName(edge: number): string {
      const nameOrIndex = this.snapshot.edges[edge + this._edgeName];
      const type = this.edgeType(edge);
      return type === 'element' || type === 'hidden' ? String(nameOrIndex) : this.snapshot.strings[nameOrIndex];
   }

   edgeTarget(edge: number): number {
      return this.snapshot.edges[edge + this._edgeTo] / this._nodeFields;
   }

   edgesFrom(ord: number): number[] {
      const result: number[] = [];
      for (let pos = this._firstEdge[ord]; pos < this._firstEdge[ord + 1]; pos += this._edgeFields) {
         result.push(pos);
      }
      return result;
   }

   // Leaves out the handles the scan itself holds through its DevTools session
   retainers(ord: number): Retainer[] {
      const result: Retainer[] = [];
      for (let r = this._retainerStart[ord]; r < this._retainerStart[ord + 1]; r++) {
         const edge = this._retainerEdge[r];
         if (!this.edgeName(edge)?.includes('DevTools console')) {
            result.push({ node: this._retainerNode[r], edge });
         }
      }
      return result;
   }

   ordinalOf(heapId: number): number | undefined {
      if (!this._ordinals) {
         this._ordinals = new Map();
         for (let i = 0; i < this.nodeCount; i++) {
            this._ordinals.set(this.nodeId(i), i);
         }
      }
      return this._ordinals.get(heapId);
   }

   isPrototype(ord: number): boolean {
      return this.retainers(ord).some(
         (retainer) => this.edgeType(retainer.edge) === 'property' && this.edgeName(retainer.edge) === 'prototype',
      );
   }

   // Returns the last 10 steps of the shortest path from the GC roots, which are node 0 in a V8 snapshot
   retainerPath(target: number): string {
      const previous = new Map<number, Retainer>();
      previous.set(target, { node: -1, edge: -1 });
      let queue = [target];
      while (queue.length && !previous.has(0)) {
         const nextQueue: number[] = [];
         for (const ord of queue) {
            for (const retainer of this.retainers(ord)) {
               if (!previous.has(retainer.node)) {
                  previous.set(retainer.node, { node: ord, edge: retainer.edge });
                  nextQueue.push(retainer.node);
               }
            }
         }
         queue = nextQueue;
      }

      let path = NO_ROOT_PATH;
      if (previous.has(0)) {
         const steps: string[] = [];
         let current = 0;
         while (current !== target) {
            const step = previous.get(current)!;
            steps.push(`${this._nodeLabel(current)} -${this.edgeType(step.edge)}:${this.edgeName(step.edge)}->`);
            current = step.node;
         }
         steps.push(this._nodeLabel(target));
         path = steps.slice(-10).join(' ');
      }
      return path;
   }

   private _nodeLabel(ord: number): string {
      return `${this.nodeType(ord)}:${this.nodeName(ord).slice(0, 50)}`;
   }
}

// Shared by the in-page functions below. Anchors each search on the pattern's first nonzero byte so the
// zero-filled stretches of WebAssembly memory do not produce a candidate at every position.
const MATCH_FN = `function findMatches(bytes, patterns, onMatch) {
   for (let idx = 0; idx < patterns.length; idx++) {
      const needle = patterns[idx];
      let anchor = 0;
      while (anchor < needle.length - 1 && needle[anchor] === 0) {
         anchor++;
      }
      const last = bytes.length - needle.length + anchor;
      for (let pos = bytes.indexOf(needle[anchor], anchor); pos !== -1 && pos <= last; pos = bytes.indexOf(needle[anchor], pos + 1)) {
         const start = pos - anchor;
         let matched = 0;
         while (matched < needle.length && bytes[start + matched] === needle[matched]) {
            matched++;
         }
         if (matched === needle.length) {
            onMatch(idx, start);
         }
      }
   }
}`;

// Chrome's inspector hides ArrayBuffers and typed arrays from object queries, so buffers are collected from
// the own properties and Map/Set entries of every ordinary object instead. Arrays of byte values are scanned too.
const WALK_FN = `function (memories, patterns) {
   ${MATCH_FN}
   const buffers = new Set();
   const numberArrays = [];
   const isByteArray = (arr) => {
      let result = arr.length >= 16 && arr.length <= 65536;
      for (let idx = 0; result && idx < arr.length; idx++) {
         const item = arr[idx];
         result = typeof item === 'number' && Number.isInteger(item) && item >= 0 && item <= 255;
      }
      return result;
   };
   const addBuffer = (value) => {
      if (value !== null && typeof value === 'object') {
         if (ArrayBuffer.isView(value)) {
            buffers.add(value.buffer);
         } else if (value instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer)) {
            buffers.add(value);
         }
      }
   };
   for (const obj of this) {
      try {
         if (Array.isArray(obj) && isByteArray(obj)) {
            numberArrays.push(obj);
         }
         for (const key of Reflect.ownKeys(obj)) {
            const desc = Reflect.getOwnPropertyDescriptor(obj, key);
            if (desc && 'value' in desc) {
               addBuffer(desc.value);
            }
         }
         if (obj instanceof Map) {
            for (const [mapKey, mapValue] of obj) {
               addBuffer(mapKey);
               addBuffer(mapValue);
            }
         } else if (obj instanceof Set) {
            for (const setValue of obj) {
               addBuffer(setValue);
            }
         }
      } catch {
         // Proxies and host objects can throw from reflection. Any buffer they hold is still counted by the coverage check.
      }
   }

   const memoryOf = new Map();
   for (const memory of memories) {
      buffers.add(memory.buffer);
      memoryOf.set(memory.buffer, memory);
   }

   const scanned = [...buffers];
   const findings = [];
   const holders = [];
   let scannedBytes = 0;
   const scanItem = (bytes, holder, location) => {
      let holderIdx = -1;
      scannedBytes += bytes.length;
      findMatches(bytes, patterns, (patternIdx, offset) => {
         if (holderIdx < 0) {
            holders.push(holder);
            holderIdx = holders.length - 1;
         }
         findings.push({ patternIdx, offset, holderIdx, location });
      });
   };
   for (const buffer of scanned) {
      const memory = memoryOf.get(buffer);
      try {
         const location = memory ? 'WebAssembly.Memory(' + buffer.byteLength + ')' : buffer.constructor.name + '(' + buffer.byteLength + ')';
         scanItem(new Uint8Array(buffer), memory || buffer, location);
      } catch {
         // A detached buffer has no bytes left to read
      }
   }
   for (const arr of numberArrays) {
      scanItem(Uint8Array.from(arr), arr, 'Array(' + arr.length + ')');
   }
   return { findings, holders, scanned, stats: { objects: this.length, buffers: scanned.length, numberArrays: numberArrays.length, scannedBytes } };
}`;

// Reads the whole underlying buffer, because a secret can sit outside the window of the view that leads to it
const READ_FN = `function (patterns) {
   ${MATCH_FN}
   const bytes = new Uint8Array(ArrayBuffer.isView(this) ? this.buffer : this);
   const hits = [];
   findMatches(bytes, patterns, (patternIdx, offset) => {
      hits.push({ patternIdx, offset });
   });
   return { length: bytes.length, hits };
}`;

const PLANT_FN = `function (pattern, canary) {
   ${MATCH_FN}
   const holders = [];
   for (const obj of this) {
      try {
         for (const key of Reflect.ownKeys(obj)) {
            const desc = Reflect.getOwnPropertyDescriptor(obj, key);
            const value = desc && desc.value;
            if (value && typeof value === 'object' && (ArrayBuffer.isView(value) || value instanceof ArrayBuffer)) {
               let found = false;
               findMatches(new Uint8Array(ArrayBuffer.isView(value) ? value.buffer : value), [pattern], () => {
                  found = true;
               });
               if (found) {
                  obj.__qcHeapScanCanary = new Uint8Array(canary);
                  holders.push((obj.constructor ? obj.constructor.name : 'Object') + '.' + String(key));
               }
            }
         }
      } catch {
         // Reflection on a Proxy runs its traps, which can throw
      }
   }
   return holders;
}`;

const OBJECT_GROUP = 'heap-scan';
// Resolving one unscanned buffer climbs at most this many retainers, and makes at most this many CDP calls
const MAX_HOLDER_DEPTH = 4;
const RESOLVE_CALL_BUDGET = 400;
// Property names CDP uses inside the scope and [[Entries]] objects it creates
const STRUCTURAL_NAMES = ['object', 'key', 'value'];

type Pattern = { secret: string; form: string; bytes: number[] };
type TextPattern = { secret: string; form: string; text: string };
type PatternHit = { patternIdx: number; offset: number };
type CallArgument = { value?: unknown; objectId?: string };
type WalkSummary = {
   findings: { patternIdx: number; offset: number; holderIdx: number; location: string }[];
   stats: { objects: number; buffers: number; numberArrays: number; scannedBytes: number };
};

async function evaluateHandle(cdp: CDPSession, expression: string): Promise<string> {
   const result = await cdp.send('Runtime.evaluate', { expression, objectGroup: OBJECT_GROUP });
   if (result.exceptionDetails || !result.result.objectId) {
      throw new Error(`heap scan: evaluating ${expression} failed`);
   }
   return result.result.objectId;
}

// Returns a handle to an array of every object that has the given prototype in its chain
async function queryObjects(cdp: CDPSession, prototypeExpression: string): Promise<string> {
   const result = await cdp.send('Runtime.queryObjects', {
      prototypeObjectId: await evaluateHandle(cdp, prototypeExpression),
      objectGroup: OBJECT_GROUP,
   });
   return result.objects.objectId!;
}

async function callOn<T>(
   cdp: CDPSession,
   objectId: string,
   functionDeclaration: string,
   args: CallArgument[],
   returnByValue: boolean,
): Promise<{ value: T; objectId: string | undefined }> {
   const result = await cdp.send('Runtime.callFunctionOn', {
      objectId,
      functionDeclaration,
      arguments: args,
      returnByValue,
      objectGroup: OBJECT_GROUP,
   });
   if (result.exceptionDetails) {
      throw new Error(`heap scan: in-page call failed: ${result.exceptionDetails.exception?.description ?? 'unknown'}`);
   }
   return { value: result.result.value as T, objectId: result.result.objectId };
}

async function heapIdOf(cdp: CDPSession, objectId: string): Promise<number> {
   return Number((await cdp.send('HeapProfiler.getHeapObjectId', { objectId })).heapSnapshotObjectId);
}

async function heapIdsOf(cdp: CDPSession, arrayId: string): Promise<number[]> {
   const props = await cdp.send('Runtime.getProperties', { objectId: arrayId, ownProperties: true });
   const ids: number[] = [];
   for (const prop of props.result) {
      if (/^\d+$/.test(prop.name) && prop.value?.objectId) {
         ids[Number(prop.name)] = await heapIdOf(cdp, prop.value.objectId);
      }
   }
   return ids;
}

async function propertyHandle(cdp: CDPSession, objectId: string, name: string): Promise<string> {
   const props = await cdp.send('Runtime.getProperties', { objectId, ownProperties: true });
   const handle = props.result.find((prop) => prop.name === name)?.value?.objectId;
   if (!handle) {
      throw new Error(`heap scan: missing ${name} in scan result`);
   }
   return handle;
}

async function takeSnapshot(cdp: CDPSession): Promise<HeapSnapshot> {
   const chunks: string[] = [];
   const onChunk = (event: { chunk: string }) => chunks.push(event.chunk);
   cdp.on('HeapProfiler.addHeapSnapshotChunk', onChunk);
   await cdp.send('HeapProfiler.takeHeapSnapshot', { reportProgress: false });
   cdp.off('HeapProfiler.addHeapSnapshotChunk', onChunk);
   return JSON.parse(chunks.join('')) as HeapSnapshot;
}

// Development builds keep destroyed views reachable for debugging, which shows up as false leaks
async function assertOptimizedBuild(cdp: CDPSession): Promise<void> {
   const result = await cdp.send('Runtime.evaluate', { expression: "typeof ng !== 'undefined'", returnByValue: true });
   if (result.result.value === true) {
      throw new Error('heap scans need the optimized test build; run them with pnpm test:secrets');
   }
}

// Reads a buffer that the walk could not reach. Examples are buffers held only by a closure variable, a #private
// field, a WeakMap value or a promise result. The search starts at the nearest objects that retain the buffer.
// From an object in the snapshot, it reads only the properties whose snapshot edges lead toward the buffer.
// It always reads the internal properties that CDP adds, such as [[Scopes]] and [[Entries]], because those
// are not in the snapshot.
async function resolveBuffer(
   cdp: CDPSession,
   graph: HeapGraph,
   bufferOrd: number,
   patterns: number[][],
): Promise<{ hits: PatternHit[]; via: string } | undefined> {
   const views = graph
      .retainers(bufferOrd)
      .filter((retainer) => graph.edgeName(retainer.edge) === 'buffer')
      .map((retainer) => retainer.node);
   const targets = [bufferOrd, ...views];
   const targetIds = new Set(targets.map((ord) => graph.nodeId(ord)));

   const depthOf = new Map<number, number>(targets.map((ord) => [ord, 0]));
   let frontier = targets;
   for (let depth = 1; depth <= MAX_HOLDER_DEPTH; depth++) {
      const next: number[] = [];
      for (const ord of frontier) {
         for (const retainer of graph.retainers(ord)) {
            if (!depthOf.has(retainer.node)) {
               depthOf.set(retainer.node, depth);
               next.push(retainer.node);
            }
         }
      }
      frontier = next;
   }
   const onPath = new Set(depthOf.keys());
   // Objects that CDP creates have no snapshot edges. Inside them, only the names of edges on these paths are
   // read, for example closure variable names.
   const pathNames = new Set(STRUCTURAL_NAMES);
   for (const ord of onPath) {
      for (const edge of graph.edgesFrom(ord)) {
         if (onPath.has(graph.edgeTarget(edge))) {
            pathNames.add(graph.edgeName(edge));
         }
      }
   }
   const directNames = new Set(
      targets.flatMap((ord) => graph.retainers(ord).map((retainer) => graph.edgeName(retainer.edge))),
   );
   const holders = [...depthOf.entries()]
      .filter(([ord, depth]) => {
         const type = graph.nodeType(ord);
         return depth > 0 && (type === 'object' || type === 'closure') && !graph.nodeName(ord).startsWith('system /');
      })
      .sort((left, right) => left[1] - right[1])
      .map(([ord]) => ord);

   let budget = RESOLVE_CALL_BUDGET;
   // Snapshot nodes already searched, which also stops constructor and prototype cycles
   const visited = new Set<number>();
   const descend = async (
      objectId: string,
      ord: number | undefined,
      depth: number,
      path: string,
   ): Promise<{ hits: PatternHit[]; via: string } | undefined> => {
      let found: { hits: PatternHit[]; via: string } | undefined;
      if (budget > 0) {
         budget--;
         const props = await cdp.send('Runtime.getProperties', { objectId, ownProperties: true });
         const towardTarget =
            ord === undefined
               ? pathNames
               : new Set(
                    graph
                       .edgesFrom(ord)
                       .filter((edge) => onPath.has(graph.edgeTarget(edge)))
                       .map((edge) => graph.edgeName(edge)),
                 );
         const leadsToTarget = (name: string) => towardTarget.has(name) || (ord === undefined && /^\d+$/.test(name));
         // Order: names of snapshot edges into the buffer or its views, then internal properties such as
         // [[Scopes]] and [[Entries]], then the rest
         const candidates = [
            ...(props.internalProperties ?? []),
            ...props.result.filter((prop) => leadsToTarget(prop.name)),
            ...(props.privateProperties ?? []).filter((prop) => leadsToTarget(prop.name)),
         ].sort((left, right) => Number(!directNames.has(left.name)) - Number(!directNames.has(right.name)));

         // Breadth first: a scope object can list many functions next to the buffer's variable, and searching
         // each function first would use up the call budget before the variable is checked
         const children: { objectId: string; ord: number | undefined; name: string }[] = [];
         for (const prop of candidates) {
            const childId = prop.value?.objectId;
            if (!found && childId && budget > 0) {
               budget--;
               // CDP cannot give heap ids for the scope objects it creates, which have no snapshot node anyway
               const heapId = await heapIdOf(cdp, childId).catch(() => undefined);
               if (heapId !== undefined && targetIds.has(heapId)) {
                  const read = await callOn<{ hits: PatternHit[] }>(cdp, childId, READ_FN, [{ value: patterns }], true);
                  found = { hits: read.value.hits, via: `${path}.${prop.name}` };
               } else {
                  const childOrd = heapId === undefined ? undefined : graph.ordinalOf(heapId);
                  children.push({ objectId: childId, ord: childOrd, name: prop.name });
               }
            }
         }
         for (const child of children) {
            const searchable = child.ord === undefined || (onPath.has(child.ord) && !visited.has(child.ord));
            if (!found && depth > 1 && searchable) {
               if (child.ord !== undefined) {
                  visited.add(child.ord);
               }
               found = await descend(child.objectId, child.ord, depth - 1, `${path}.${child.name}`);
            }
         }
      }
      return found;
   };

   let resolved: { hits: PatternHit[]; via: string } | undefined;
   for (const holder of holders) {
      if (!resolved && budget > 0 && !visited.has(holder)) {
         visited.add(holder);
         budget--;
         try {
            const handle = await cdp.send('HeapProfiler.getObjectByHeapObjectId', {
               objectId: String(graph.nodeId(holder)),
               objectGroup: OBJECT_GROUP,
            });
            if (handle.result.objectId) {
               resolved = await descend(handle.result.objectId, holder, MAX_HOLDER_DEPTH + 2, graph.nodeName(holder));
            }
         } catch {
            // Internal nodes such as contexts and hash tables are not available as JS objects
         }
      }
   }
   return resolved;
}

function findStrings(graph: HeapGraph, textPatterns: TextPattern[]): Finding[] {
   const findings: Finding[] = [];
   const shortest = Math.min(...textPatterns.map((pattern) => pattern.text.length));
   const stringTypes = new Set(['string', 'concatenated string', 'sliced string']);
   graph.snapshot.strings.forEach((str, strIdx) => {
      if (str.length >= shortest) {
         const matches = textPatterns.filter((pattern) => str.includes(pattern.text));
         if (matches.length) {
            const owners: number[] = [];
            for (let i = 0; i < graph.nodeCount && owners.length < 2; i++) {
               if (graph.nameIndex(i) === strIdx && stringTypes.has(graph.nodeType(i))) {
                  owners.push(i);
               }
            }
            const paths = owners.map((ord) => graph.retainerPath(ord));
            const retainers = paths.length ? paths.join(' | ') : '(only a property or class name)';
            for (const pattern of matches) {
               findings.push({
                  secret: pattern.secret,
                  form: pattern.form,
                  kind: 'string',
                  location: `string(${str.length})`,
                  retainers,
                  reachable: !paths.length || paths.some((path) => path !== NO_ROOT_PATH),
               });
            }
         }
      }
   });
   return findings;
}

// Finds every copy of the secrets in the page's JavaScript heap and WebAssembly memories. Strings come from a
// heap snapshot and bytes from walking the heap. Any buffer in the snapshot that the walk missed is read
// through CDP, or reported as unresolved when that fails.
export async function scanHeap(page: Page, label: string, secrets: Secret[]): Promise<HeapScan> {
   const started = Date.now();
   const patterns: Pattern[] = secrets.flatMap((secret) =>
      secret.bytes.map(([form, bytes]) => ({ secret: secret.name, form, bytes })),
   );
   const patternBytes = patterns.map((pattern) => pattern.bytes);
   const textPatterns: TextPattern[] = secrets.flatMap((secret) =>
      secret.texts.map(([form, text]) => ({ secret: secret.name, form, text })),
   );

   const cdp = await page.context().newCDPSession(page);
   try {
      await cdp.send('Runtime.enable');
      await cdp.send('HeapProfiler.enable');
      await assertOptimizedBuild(cdp);
      await cdp.send('HeapProfiler.collectGarbage');

      const objects = await queryObjects(cdp, 'Object.prototype');
      const memories = await queryObjects(cdp, 'WebAssembly.Memory.prototype');
      const walk = await callOn<undefined>(
         cdp,
         objects,
         WALK_FN,
         [{ objectId: memories }, { value: patternBytes }],
         false,
      );
      const walkId = walk.objectId!;
      const summary = await callOn<WalkSummary>(
         cdp,
         walkId,
         'function () { return { findings: this.findings, stats: this.stats }; }',
         [],
         true,
      );
      const walked = Date.now();

      const graph = new HeapGraph(await takeSnapshot(cdp));
      const snapshotted = Date.now();
      // The snapshot's garbage collection moves objects and renumbers them, so heap ids are read only afterward
      const holderIds = summary.value.findings.length
         ? await heapIdsOf(cdp, await propertyHandle(cdp, walkId, 'holders'))
         : [];
      const scannedIds = new Set(await heapIdsOf(cdp, await propertyHandle(cdp, walkId, 'scanned')));

      const findings: Finding[] = summary.value.findings.map((hit) => {
         const holderOrd = graph.ordinalOf(holderIds[hit.holderIdx]);
         const retainers = holderOrd === undefined ? '(not in snapshot)' : graph.retainerPath(holderOrd);
         return {
            secret: patterns[hit.patternIdx].secret,
            form: patterns[hit.patternIdx].form,
            kind: 'bytes',
            location: `${hit.location} @${hit.offset}`,
            retainers,
            reachable: retainers !== NO_ROOT_PATH,
         };
      });

      const unresolved: string[] = [];
      let unscannedCount = 0;
      for (let i = 0; i < graph.nodeCount; i++) {
         const name = graph.nodeName(i);
         const isBuffer = graph.nodeType(i) === 'object' && (name === 'ArrayBuffer' || name === 'SharedArrayBuffer');
         if (isBuffer && !scannedIds.has(graph.nodeId(i)) && !graph.isPrototype(i)) {
            unscannedCount++;
            const retainers = graph.retainerPath(i);
            const resolved = await resolveBuffer(cdp, graph, i, patternBytes);
            if (resolved) {
               for (const hit of resolved.hits) {
                  findings.push({
                     secret: patterns[hit.patternIdx].secret,
                     form: patterns[hit.patternIdx].form,
                     kind: 'bytes',
                     location: `${name} via ${resolved.via} @${hit.offset}`,
                     retainers,
                     reachable: retainers !== NO_ROOT_PATH,
                  });
               }
            } else if (retainers !== NO_ROOT_PATH) {
               unresolved.push(retainers);
            }
         }
      }
      findings.push(...findStrings(graph, textPatterns));

      const stats = summary.value.stats;
      return {
         label,
         findings,
         unresolved,
         summary:
            `objects=${stats.objects} buffers=${stats.buffers} byteArrays=${stats.numberArrays} ` +
            `bytes=${(stats.scannedBytes / 1e6).toFixed(1)}MB unscanned=${unscannedCount} ` +
            `strings=${graph.snapshot.strings.length} walk=${walked - started}ms ` +
            `snapshot=${snapshotted - walked}ms resolve=${Date.now() - snapshotted}ms`,
      };
   } finally {
      await cdp.detach();
   }
}

// Puts a canary next to each holder of the given bytes. Finding the canary in a later scan, after the secret
// is gone, shows that the scan still reaches the object that held the secret.
export async function plantCanaryNextTo(page: Page, secretBytes: Uint8Array, canary: Uint8Array): Promise<string[]> {
   const cdp = await page.context().newCDPSession(page);
   try {
      await cdp.send('Runtime.enable');
      await cdp.send('HeapProfiler.enable');
      await cdp.send('HeapProfiler.collectGarbage');
      const objects = await queryObjects(cdp, 'Object.prototype');
      const planted = await callOn<string[]>(
         cdp,
         objects,
         PLANT_FN,
         [{ value: [...secretBytes] }, { value: [...canary] }],
         true,
      );
      return planted.value;
   } finally {
      await cdp.detach();
   }
}

// Calls a function in the page with argument values sent over CDP, so the values never appear in script source
export async function callInPage<T>(page: Page, functionDeclaration: string, args: unknown[]): Promise<T> {
   const cdp = await page.context().newCDPSession(page);
   try {
      await cdp.send('Runtime.enable');
      const global = await evaluateHandle(cdp, 'globalThis');
      const result = await callOn<T>(
         cdp,
         global,
         functionDeclaration,
         args.map((value) => ({ value })),
         true,
      );
      return result.value;
   } finally {
      await cdp.detach();
   }
}
