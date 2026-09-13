import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { NewUserComponent } from './newuser.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('NewuserComponent', () => {
   let component: NewUserComponent;
   let fixture: ComponentFixture<NewUserComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [NewUserComponent, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      fixture = TestBed.createComponent(NewUserComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the user name away from browser text assistance', () => {
      const userName = fixture.nativeElement.querySelector('#userName');
      expect(userName.getAttribute('spellcheck')).toBe('false');
      expect(userName.getAttribute('autocomplete')).toBe('off');
      expect(userName.getAttribute('autocorrect')).toBe('off');
      expect(userName.getAttribute('autocapitalize')).toBe('off');
   });
});
