import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { RecoveryComponent } from './recovery.component';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';

describe('RecoveryComponent', () => {
   let component: RecoveryComponent;
   let fixture: ComponentFixture<RecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [RecoveryComponent],
         providers: [
            provideRouter([]),
            provideHttpClient(withXhr(), withInterceptorsFromDi()),
            provideHttpClientTesting(),
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(RecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
