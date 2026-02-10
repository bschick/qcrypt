import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FaqsComponent } from './faqs.component';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule } from '@angular/router';

describe('FaqsComponent', () => {
   let component: FaqsComponent;
   let fixture: ComponentFixture<FaqsComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [FaqsComponent, NoopAnimationsModule, RouterModule.forRoot([]),]
      })
         .compileComponents();

      fixture = TestBed.createComponent(FaqsComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
