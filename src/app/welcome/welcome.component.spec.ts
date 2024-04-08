import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { WelcomeComponent } from './welcome.component';
import { RouterModule } from '@angular/router';

describe('WelcomeComponent', () => {
   let component: WelcomeComponent;
   let fixture: ComponentFixture<WelcomeComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [WelcomeComponent, NoopAnimationsModule, RouterModule.forRoot([]), HttpClientTestingModule]
      })
         .compileComponents();

      fixture = TestBed.createComponent(WelcomeComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
