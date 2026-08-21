import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FaqsComponent } from './faqs.component';
import { ActivatedRoute, type ParamMap, convertToParamMap, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('FaqsComponent', () => {
   let paramMapSubject: BehaviorSubject<ParamMap>;

   async function createFixture(
      initialId: string | null = null,
   ): Promise<{ fixture: ComponentFixture<FaqsComponent>; component: FaqsComponent }> {
      paramMapSubject = new BehaviorSubject<ParamMap>(convertToParamMap(initialId === null ? {} : { id: initialId }));
      await TestBed.configureTestingModule({
         imports: [FaqsComponent, NoopAnimationsModule],
         providers: [
            provideRouter([]),
            {
               provide: ActivatedRoute,
               useValue: {
                  paramMap: paramMapSubject,
                  snapshot: { queryParamMap: convertToParamMap({}) },
               },
            },
         ],
      }).compileComponents();

      const fixture = TestBed.createComponent(FaqsComponent);
      fixture.detectChanges();
      return { fixture, component: fixture.componentInstance };
   }

   it('should create', async () => {
      const { component } = await createFixture();
      expect(component).toBeTruthy();
   });

   it('has unique 3-digit hex IDs for all FAQs', async () => {
      const { component } = await createFixture();
      const ids = component.dataSource.data.map((faq) => faq.id);
      expect(ids.length).toBeGreaterThan(0);

      const idSet = new Set<string>();
      for (const id of ids) {
         expect(id).toMatch(/^[0-9a-f]{3}$/);
         expect(idSet.has(id)).toBe(false);
         idSet.add(id);
      }
   });

   it('loads full FAQ list when no id route param is present', async () => {
      const { component } = await createFixture();
      expect(component.singleFaqId).toBeNull();
      expect(component.notFound).toBe(false);
      expect(component.dataSource.data.length).toBeGreaterThan(1);
   });

   it('filters to a single expanded FAQ when a valid id route param is provided', async () => {
      const { component } = await createFixture('0b2');
      expect(component.singleFaqId).toBe('0b2');
      expect(component.notFound).toBe(false);
      expect(component.dataSource.data.length).toBe(1);
      expect(component.dataSource.data[0].id).toBe('0b2');
      expect(component.expandedPositions).toContain(component.dataSource.data[0].position);
   });

   it('matches id case-insensitively', async () => {
      const { component } = await createFixture('0B2');
      expect(component.singleFaqId).toBe('0b2');
      expect(component.notFound).toBe(false);
      expect(component.dataSource.data.length).toBe(1);
      expect(component.dataSource.data[0].id).toBe('0b2');
   });

   it('handles invalid id gracefully with notFound set', async () => {
      const { component } = await createFixture('invalid_id');
      expect(component.singleFaqId).toBe('invalid_id');
      expect(component.notFound).toBe(true);
      expect(component.dataSource.data.length).toBe(0);
   });

   it('reacts dynamically when route params change from single FAQ back to all FAQs', async () => {
      const { component } = await createFixture('0b2');
      expect(component.dataSource.data.length).toBe(1);

      paramMapSubject.next(convertToParamMap({}));
      expect(component.singleFaqId).toBeNull();
      expect(component.notFound).toBe(false);
      expect(component.dataSource.data.length).toBeGreaterThan(1);
   });

   it('generates correct FAQ direct URL with getFaqUrl', async () => {
      const { component } = await createFixture();
      const url = component.getFaqUrl('0b2');
      expect(url).toContain('/help/faqs/0b2');
   });
});
