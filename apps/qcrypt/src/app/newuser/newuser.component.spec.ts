import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { NewUserComponent } from './newuser.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('NewuserComponent', () => {
   let component: NewUserComponent;
   let fixture: ComponentFixture<NewUserComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
    imports: [NewUserComponent, RouterModule.forRoot([]), NoopAnimationsModule],
    providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
})
         .compileComponents();

      fixture = TestBed.createComponent(NewUserComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
