import { ComponentFixture, TestBed } from '@angular/core/testing';
import { EditableComponent } from './editable.component';

describe('EditableComponent', () => {
   let component: EditableComponent;
   let fixture: ComponentFixture<EditableComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [EditableComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(EditableComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the edited value away from browser text assistance', () => {
      const input = fixture.nativeElement.querySelector('input');
      expect(input.getAttribute('spellcheck')).toBe('false');
      expect(input.getAttribute('autocomplete')).toBe('off');
      expect(input.getAttribute('autocorrect')).toBe('off');
      expect(input.getAttribute('autocapitalize')).toBe('off');
   });

   it('consumes the enter and escape keys that end an edit', () => {
      for (const method of ['acceptEdit', 'cancelEdit'] as const) {
         component.tryMakeEditable();
         const event = new KeyboardEvent('keydown', { key: 'Enter', cancelable: true });
         component[method](event);
         expect(event.defaultPrevented).toBe(true);
      }
   });
});
