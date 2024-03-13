import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from "@angular/router/testing";
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { NewUserComponent } from './newuser.component';

describe('NewuserComponent', () => {
   let component: NewUserComponent;
   let fixture: ComponentFixture<NewUserComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [NewUserComponent, RouterTestingModule, NoopAnimationsModule, HttpClientTestingModule]
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
