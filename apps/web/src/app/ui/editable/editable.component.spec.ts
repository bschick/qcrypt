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

   it('consumes the enter and escape keys that end an edit', () => {
      for (const method of ['acceptEdit', 'cancelEdit'] as const) {
         component.tryMakeEditable();
         const event = new KeyboardEvent('keydown', { key: 'Enter', cancelable: true });
         component[method](event);
         expect(event.defaultPrevented).toBe(true);
      }
   });
});
