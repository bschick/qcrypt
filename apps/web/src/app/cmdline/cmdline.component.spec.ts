import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CmdLineComponent } from './cmdline.component';
import { RouterModule } from '@angular/router';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('CmdLineComponent', () => {
   let component: CmdLineComponent;
   let fixture: ComponentFixture<CmdLineComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CmdLineComponent, NoopAnimationsModule, RouterModule.forRoot([])],
      }).compileComponents();

      fixture = TestBed.createComponent(CmdLineComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the user credential away from browser text assistance', () => {
      component.showProgress = false;
      component.error = '';
      fixture.detectChanges();

      const credential = fixture.nativeElement.querySelector('#credential');
      expect(credential.getAttribute('spellcheck')).toBe('false');
      expect(credential.getAttribute('autocomplete')).toBe('off');
      expect(credential.getAttribute('autocorrect')).toBe('off');
      expect(credential.getAttribute('autocapitalize')).toBe('off');
   });
});
