import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StrengthMeterComponent } from './strengthmeter.component';

describe('StrengthMeterComponent', () => {
   let component: StrengthMeterComponent;
   let fixture: ComponentFixture<StrengthMeterComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [StrengthMeterComponent]
      })
         .compileComponents();

      fixture = TestBed.createComponent(StrengthMeterComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
