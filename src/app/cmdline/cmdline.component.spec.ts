import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CmdLineComponent } from './cmdline.component';
import { RouterModule } from '@angular/router';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('CmdLineComponent', () => {
   let component: CmdLineComponent;
   let fixture: ComponentFixture<CmdLineComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CmdLineComponent, NoopAnimationsModule, RouterModule.forRoot([]),]
      })
         .compileComponents();

      fixture = TestBed.createComponent(CmdLineComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
