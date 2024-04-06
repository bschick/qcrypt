import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ShowRecoveryComponent } from './showrecovery.component';

describe('ShowRecoveryComponent', () => {
   let component: ShowRecoveryComponent;
   let fixture: ComponentFixture<ShowRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [ShowRecoveryComponent]
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
