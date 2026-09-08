import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ShowRecoveryComponent } from './showrecovery.component';
import { RouterModule } from '@angular/router';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';

describe('ShowRecoveryComponent', () => {
   let component: ShowRecoveryComponent;
   let fixture: ComponentFixture<ShowRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [
            ShowRecoveryComponent,
            NoopAnimationsModule,
            RouterModule.forRoot([{ path: 'regenrecovery', children: [] }]),
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(ShowRecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the recovery words away from browser text assistance', () => {
      const wordsArea = fixture.nativeElement.querySelector('#wordsArea');
      expect(wordsArea.getAttribute('spellcheck')).toBe('false');
      expect(wordsArea.getAttribute('autocomplete')).toBe('off');
      expect(wordsArea.getAttribute('autocorrect')).toBe('off');
      expect(wordsArea.getAttribute('autocapitalize')).toBe('off');
   });
});
