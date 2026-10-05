import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FaqsComponent } from './faqs.component';
import { provideRouter } from '@angular/router';

describe('FaqsComponent', () => {
   async function createFixture(
      initialId: string | null = null,
      search: string | null = null,
   ): Promise<{ fixture: ComponentFixture<FaqsComponent>; component: FaqsComponent }> {
      await TestBed.configureTestingModule({
         imports: [FaqsComponent],
         providers: [provideRouter([])],
      }).compileComponents();

      const fixture = TestBed.createComponent(FaqsComponent);
      if (initialId !== null) {
         fixture.componentRef.setInput('id', initialId);
      }
      if (search !== null) {
         fixture.componentRef.setInput('search', search);
      }
      fixture.detectChanges();
      return { fixture, component: fixture.componentInstance };
   }

   function questionRows(fixture: ComponentFixture<FaqsComponent>): HTMLElement[] {
      return [...fixture.nativeElement.querySelectorAll('tr.element-row')];
   }

   function openAnswers(fixture: ComponentFixture<FaqsComponent>): HTMLElement[] {
      return [...fixture.nativeElement.querySelectorAll('.element-detail.expanded')];
   }

   function searchInput(fixture: ComponentFixture<FaqsComponent>): HTMLInputElement {
      return fixture.nativeElement.querySelector('.search-input');
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
      expect(component.singleFaqId()).toBeNull();
      expect(component.notFound()).toBe(false);
      expect(component.dataSource.data.length).toBeGreaterThan(1);
   });

   it('filters to a single expanded FAQ when a valid id route param is provided', async () => {
      const { component } = await createFixture('0b2');
      expect(component.singleFaqId()).toBe('0b2');
      expect(component.notFound()).toBe(false);
      expect(component.dataSource.data.length).toBe(1);
      expect(component.dataSource.data[0].id).toBe('0b2');
      expect(component.expandedPositions()).toContain(component.dataSource.data[0].position);
   });

   it('matches id case-insensitively', async () => {
      const { component } = await createFixture('0B2');
      expect(component.singleFaqId()).toBe('0b2');
      expect(component.notFound()).toBe(false);
      expect(component.dataSource.data.length).toBe(1);
      expect(component.dataSource.data[0].id).toBe('0b2');
   });

   it('handles invalid id gracefully with notFound set', async () => {
      const { component } = await createFixture('invalid_id');
      expect(component.singleFaqId()).toBe('invalid_id');
      expect(component.notFound()).toBe(true);
      expect(component.dataSource.data.length).toBe(0);
   });

   it('reacts dynamically when route params change from single FAQ back to all FAQs', async () => {
      const { fixture, component } = await createFixture('0b2');
      expect(component.dataSource.data.length).toBe(1);

      fixture.componentRef.setInput('id', undefined);
      fixture.detectChanges();
      expect(component.singleFaqId()).toBeNull();
      expect(component.notFound()).toBe(false);
      expect(component.dataSource.data.length).toBeGreaterThan(1);
   });

   it('generates correct FAQ direct URL with getFaqUrl', async () => {
      const { component } = await createFixture();
      const url = component.getFaqUrl('0b2');
      expect(url).toContain('/help/faqs/0b2');
   });

   it('opens with the search from the URL applied and every answer open', async () => {
      const { fixture, component } = await createFixture(null, 'recovery');
      await fixture.whenStable();
      fixture.detectChanges();

      const shown = questionRows(fixture).length;
      expect(searchInput(fixture).value).toBe('recovery');
      expect(shown).toBeGreaterThan(0);
      expect(shown).toBeLessThan(component.dataSource.data.length);
      expect(openAnswers(fixture).length).toBe(shown);
      expect(fixture.nativeElement.querySelector('.search-clear')).not.toBeNull();
   });

   it('applies + and - terms in the search from the URL', async () => {
      const { fixture, component } = await createFixture(null, '+recovery,-words');
      await fixture.whenStable();
      fixture.detectChanges();

      const shown = questionRows(fixture).length;
      expect(shown).toBeGreaterThan(0);
      expect(shown).toBeLessThan(component.dataSource.data.length);
   });

   it('clicking a question opens its answer, and clicking again closes it', async () => {
      const { fixture } = await createFixture();
      const firstQuestion = questionRows(fixture)[0];

      firstQuestion.click();
      fixture.detectChanges();
      expect(openAnswers(fixture).length).toBe(1);

      firstQuestion.click();
      fixture.detectChanges();
      expect(openAnswers(fixture).length).toBe(0);
   });

   it('clearing the search shows every FAQ', async () => {
      const { fixture, component } = await createFixture(null, 'recovery');
      await fixture.whenStable();
      fixture.detectChanges();

      fixture.nativeElement.querySelector('.search-clear').click();
      fixture.detectChanges();
      await fixture.whenStable();
      fixture.detectChanges();

      expect(searchInput(fixture).value).toBe('');
      expect(questionRows(fixture).length).toBe(component.dataSource.data.length);
      expect(fixture.nativeElement.querySelector('.search-clear')).toBeNull();
   });

   it('clearing the search leaves focus in the search box', async () => {
      const { fixture } = await createFixture(null, 'recovery');
      await fixture.whenStable();
      fixture.detectChanges();

      const clear: HTMLButtonElement = fixture.nativeElement.querySelector('.search-clear');
      clear.focus();
      clear.click();
      fixture.detectChanges();

      expect(document.activeElement).toBe(searchInput(fixture));
   });

   it('filters when the search text changes without a key press', async () => {
      const { fixture, component } = await createFixture();
      const input = searchInput(fixture);

      input.value = 'recovery';
      input.dispatchEvent(new Event('input'));
      fixture.detectChanges();

      expect(questionRows(fixture).length).toBeLessThan(component.dataSource.data.length);
   });
});
