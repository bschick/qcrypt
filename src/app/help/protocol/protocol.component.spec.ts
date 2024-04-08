import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ProtocolComponent } from './protocol.component';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule } from '@angular/router';

describe('ProtocolComponent', () => {
   let component: ProtocolComponent;
   let fixture: ComponentFixture<ProtocolComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [ProtocolComponent,NoopAnimationsModule, RouterModule.forRoot([]),]
      })
         .compileComponents();

      fixture = TestBed.createComponent(ProtocolComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
