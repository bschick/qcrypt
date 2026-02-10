import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ShowRecoveryComponent } from './showrecovery.component';
import { RouterModule } from '@angular/router';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('ShowRecoveryComponent', () => {
   let component: ShowRecoveryComponent;
   let fixture: ComponentFixture<ShowRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [ShowRecoveryComponent, NoopAnimationsModule, RouterModule.forRoot([]),]
      })
         .compileComponents();

      fixture = TestBed.createComponent(ShowRecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
