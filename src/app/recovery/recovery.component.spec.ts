import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from "@angular/router/testing";
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { RecoveryComponent } from './recovery.component';

describe('RecoveryComponent', () => {
   let component: RecoveryComponent;
   let fixture: ComponentFixture<RecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [RecoveryComponent, RouterTestingModule, NoopAnimationsModule, HttpClientTestingModule]
      })
         .compileComponents();

      fixture = TestBed.createComponent(RecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
