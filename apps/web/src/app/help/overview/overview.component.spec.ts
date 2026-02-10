import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OverviewComponent } from './overview.component';
import { RouterModule } from '@angular/router';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('OverviewComponent', () => {
   let component: OverviewComponent;
   let fixture: ComponentFixture<OverviewComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [OverviewComponent, NoopAnimationsModule, RouterModule.forRoot([]),]
      })
         .compileComponents();

      fixture = TestBed.createComponent(OverviewComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
