import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FlowComponent } from './flow.component';
import { ActivatedRoute, ParamMap, convertToParamMap, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { FLOW_OVERVIEWS, FLOW_SUBSYSTEMS } from './flow.config';
import { parseSubscripts } from './sub-label/sub-label.component';

// Path-mode tests are driven by whatever is currently in flow.config.ts so
// renaming a FLOW_OVERVIEWS or FLOW_SUBSYSTEMS key doesn't break them. They
// always use the first entry in each map.
const overviewEntries = Object.entries(FLOW_OVERVIEWS);
const subsystemEntries = Object.entries(FLOW_SUBSYSTEMS);

describe('FlowComponent', () => {
   let queryParamMap: BehaviorSubject<ParamMap>;

   async function createFixture(initialPath: string | null = null):
      Promise<{ fixture: ComponentFixture<FlowComponent>; component: FlowComponent }> {
      queryParamMap = new BehaviorSubject<ParamMap>(
         convertToParamMap(initialPath === null ? {} : { path: initialPath }),
      );
      await TestBed.configureTestingModule({
         imports: [FlowComponent, NoopAnimationsModule],
         providers: [
            provideRouter([]),
            { provide: ActivatedRoute, useValue: { queryParamMap } },
         ],
      }).compileComponents();
      const fixture = TestBed.createComponent(FlowComponent);
      fixture.detectChanges();
      return { fixture, component: fixture.componentInstance };
   }

   it('should create', async () => {
      const { component } = await createFixture();
      expect(component).toBeTruthy();
   });

   it('starts in grid mode with single Overview crumb', async () => {
      const { component } = await createFixture();
      expect(component.mode()).toBe('grid');
      const crumbs = component.breadcrumbs();
      expect(crumbs.length).toBe(1);
      expect(crumbs[0].label).toBe('Overview');
      expect(crumbs[0].queryParams).toBeNull();
   });

   it('config has at least one overview and one subsystem', () => {
      expect(overviewEntries.length).toBeGreaterThan(0);
      expect(subsystemEntries.length).toBeGreaterThan(0);
   });

   it('renders a depth-2 path with the right breadcrumbs and current item', async () => {
      const [overviewId, overview] = overviewEntries[0];
      const [subId, sub] = subsystemEntries[0];
      const { component } = await createFixture(`${overviewId},${subId}`);
      expect(component.mode()).toBe('node');
      expect(component.path()).toEqual([overviewId, subId]);
      expect(component.currentItem()?.label).toBe(sub.label);
      const crumbs = component.breadcrumbs();
      expect(crumbs.map(c => c.label)).toEqual(['Overview', overview.label, sub.label]);
      expect(crumbs[0].queryParams).toEqual({ path: null });
      expect(crumbs[1].queryParams).toEqual({ path: overviewId });
      expect(crumbs[2].queryParams).toBeNull();
   });

   it('truncates invalid path segments back to the longest valid prefix', async () => {
      const [overviewId] = overviewEntries[0];
      const [subId] = subsystemEntries[0];
      // 'zz' is not a hex byte and so cannot match any FLOW_SUBSYSTEMS key.
      const { component } = await createFixture(`${overviewId},${subId},zz,yy`);
      expect(component.path()).toEqual([overviewId, subId]);
   });
});

describe('parseSubscripts', () => {
   it('returns a single non-subscript segment when no underscores', () => {
      expect(parseSubscripts('Verify MAC tag')).toEqual([
         { text: 'Verify MAC tag', sub: false },
      ]);
   });

   it('treats _X as a subscript', () => {
      expect(parseSubscripts('Create m_E')).toEqual([
         { text: 'Create m', sub: false },
         { text: 'E', sub: true },
      ]);
   });

   it('captures multi-char alphanumeric subscripts', () => {
      expect(parseSubscripts('Derive k_M0')).toEqual([
         { text: 'Derive k', sub: false },
         { text: 'M0', sub: true },
      ]);
   });

   it('handles text after a subscript', () => {
      expect(parseSubscripts('Create ad_F (block 0)')).toEqual([
         { text: 'Create ad', sub: false },
         { text: 'F', sub: true },
         { text: ' (block 0)', sub: false },
      ]);
   });

   it('treats an underscore at end of string as literal', () => {
      expect(parseSubscripts('lonely_')).toEqual([
         { text: 'lonely_', sub: false },
      ]);
   });
});
