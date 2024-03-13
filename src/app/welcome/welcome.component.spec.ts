import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from "@angular/router/testing";
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { WelcomeComponent } from './welcome.component';

describe('WelcomeComponent', () => {
   let component: WelcomeComponent;
   let fixture: ComponentFixture<WelcomeComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [WelcomeComponent, RouterTestingModule, NoopAnimationsModule, HttpClientTestingModule]
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
