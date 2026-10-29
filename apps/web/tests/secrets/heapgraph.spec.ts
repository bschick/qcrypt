import { test, expect } from '@playwright/test';
import { findStrings, HeapGraph, type HeapSnapshot } from './heapscan';

const NODE_TYPES = ['synthetic', 'object', 'string'];
const EDGE_TYPES = ['property', 'internal', 'weak'];
const NODE_FIELDS = ['type', 'name', 'id', 'edge_count'];

type EdgeSpec = [type: string, name: string, targetPos: number];
type NodeSpec = [type: string, name: string, edges: EdgeSpec[]];

// Heap ids differ from node positions in V8 snapshots too, so code that mixes them up fails here
const heapIdAt = (pos: number): number => pos + 1;

function snapshotOf(nodes: NodeSpec[]): HeapSnapshot {
   const strings: string[] = [];
   const stringIndex = (text: string): number => {
      if (!strings.includes(text)) {
         strings.push(text);
      }
      return strings.indexOf(text);
   };
   const snapshot: HeapSnapshot = {
      snapshot: {
         meta: {
            node_fields: NODE_FIELDS,
            node_types: [NODE_TYPES],
            edge_fields: ['type', 'name_or_index', 'to_node'],
            edge_types: [EDGE_TYPES],
         },
      },
      nodes: [],
      edges: [],
      strings,
   };
   nodes.forEach(([type, name, edges], pos) => {
      snapshot.nodes.push(NODE_TYPES.indexOf(type), stringIndex(name), heapIdAt(pos), edges.length);
      for (const [edgeType, edgeName, targetPos] of edges) {
         snapshot.edges.push(EDGE_TYPES.indexOf(edgeType), stringIndex(edgeName), targetPos * NODE_FIELDS.length);
      }
   });
   return snapshot;
}

const PAGE = 1;
const GLOBAL_HANDLES = 2;
const SCAN_HANDLE = 3;
const DEVTOOLS_HANDLE = 4;
const ORPHAN = 5;
const TEXT = 'canary text';
const PATTERNS = [{ secret: 'canary', form: 'text', text: TEXT }];

// Node 0 is the root. It reaches PAGE through a property. Only DevTools handles reach SCAN_HANDLE and
// DEVTOOLS_HANDLE. The scan holds SCAN_HANDLE. Nothing retains ORPHAN. copyHolders lists the holder of each copy of
// TEXT, with undefined for a copy that no node holds. Each holder reaches its copy through an edge of holderEdgeType.
function graphWithCopies(copyHolders: (number | undefined)[], holderEdgeType = 'property'): HeapGraph {
   const nodes: NodeSpec[] = [
      [
         'synthetic',
         '',
         [
            ['property', 'window', PAGE],
            ['internal', '(Global handles)', GLOBAL_HANDLES],
         ],
      ],
      ['object', 'Window', []],
      [
         'synthetic',
         '(Global handles)',
         [
            ['internal', '1 / DevTools console', SCAN_HANDLE],
            ['internal', '2 / DevTools console', DEVTOOLS_HANDLE],
         ],
      ],
      ['object', 'ScanResult', []],
      ['object', 'Object', []],
      ['object', 'Orphan', []],
   ];
   copyHolders.forEach((holder, index) => {
      if (holder !== undefined) {
         nodes[holder][2].push([holderEdgeType, `copy${index}`, nodes.length]);
      }
      nodes.push(['string', TEXT, []]);
   });
   return new HeapGraph(snapshotOf(nodes), [heapIdAt(SCAN_HANDLE)]);
}

test.describe('heap graph reachability', () => {
   test('a string held only by a DevTools handle is unreachable', () => {
      const [finding] = findStrings(graphWithCopies([DEVTOOLS_HANDLE]), PATTERNS);
      expect(finding.reachable).toBe(false);
      expect(finding.retainers).toContain('DevTools console');
   });

   test("a string held only by the scan's own DevTools handle counts as reachable", () => {
      const [finding] = findStrings(graphWithCopies([SCAN_HANDLE]), PATTERNS);
      expect(finding.reachable).toBe(true);
   });

   test("a string held only by the scan's own DevTools handle reports that handle", () => {
      const [finding] = findStrings(graphWithCopies([SCAN_HANDLE]), PATTERNS);
      expect(finding.retainers).toContain('object:ScanResult (held by the scan) -property:copy0->');
   });

   test('a string that no node holds counts as reachable', () => {
      const [finding] = findStrings(graphWithCopies([undefined]), PATTERNS);
      expect(finding.reachable).toBe(true);
   });

   test('a string is reachable when only its third copy is', () => {
      const [finding] = findStrings(graphWithCopies([DEVTOOLS_HANDLE, DEVTOOLS_HANDLE, PAGE]), PATTERNS);
      expect(finding.reachable).toBe(true);
   });

   test('a string held only through a weak reference reports that path', () => {
      const [finding] = findStrings(graphWithCopies([PAGE], 'weak'), PATTERNS);
      expect(finding.reachable).toBe(true);
      expect(finding.retainers).toContain('object:Window -weak:copy0->');
   });

   test('a string held by an object that nothing retains reports that object', () => {
      const [finding] = findStrings(graphWithCopies([ORPHAN]), PATTERNS);
      expect(finding.reachable).toBe(true);
      expect(finding.retainers).toContain('object:Orphan -property:copy0->');
   });
});
