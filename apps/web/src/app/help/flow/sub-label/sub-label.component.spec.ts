import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SubLabelComponent } from './sub-label.component';

describe('SubLabelComponent', () => {
   let component: SubLabelComponent;
   let fixture: ComponentFixture<SubLabelComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [SubLabelComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(SubLabelComponent);
      fixture.componentRef.setInput('text', 'Create m_E');
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('renders subscripts as <sub> elements', () => {
      const host: HTMLElement = fixture.nativeElement;
      const subs = host.querySelectorAll('sub');
      expect(subs.length).toBe(1);
      expect(subs[0].textContent?.trim()).toBe('E');
      expect(host.textContent?.trim()).toBe('Create mE');
   });
});
