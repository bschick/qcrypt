import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CmdLineComponent } from './cmdline.component';
import { provideRouter } from '@angular/router';

describe('CmdLineComponent', () => {
   let component: CmdLineComponent;
   let fixture: ComponentFixture<CmdLineComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CmdLineComponent],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(CmdLineComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the user credential away from browser text assistance', () => {
      // @ts-expect-error — exercising protected state to render the credential field
      component.showProgress.set(false);
      // @ts-expect-error — exercising protected state to render the credential field
      component.error.set('');
      fixture.detectChanges();

      const credential = fixture.nativeElement.querySelector('#credential');
      expect(credential.getAttribute('spellcheck')).toBe('false');
      expect(credential.getAttribute('autocomplete')).toBe('off');
      expect(credential.getAttribute('autocorrect')).toBe('off');
      expect(credential.getAttribute('autocapitalize')).toBe('off');
   });
});
