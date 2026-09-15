import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CredentialsComponent } from './credentials.component';
import { RouterModule } from '@angular/router';

describe('CredentialsComponent', () => {
   let component: CredentialsComponent;
   let fixture: ComponentFixture<CredentialsComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CredentialsComponent, RouterModule.forRoot([])],
      }).compileComponents();

      fixture = TestBed.createComponent(CredentialsComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
