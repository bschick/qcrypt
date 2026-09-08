import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { PasswordDialog, type PwdDialogData } from './dialogs';

// Entering a password, with hiding off so the field is a plain text input
const DIALOG_DATA: PwdDialogData = {
   message: '',
   hint: '',
   encrypting: true,
   minStrength: 3,
   hidePwd: false,
   loopCount: 1,
   loops: 1,
   checkPwned: false,
   welcomed: true,
   userName: 'tester',
   cipherMode: 'AEGIS-256',
   usedPasswords: [],
};

describe('PasswordDialog', () => {
   let component: PasswordDialog;
   let fixture: ComponentFixture<PasswordDialog>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [PasswordDialog, NoopAnimationsModule],
         providers: [
            { provide: MatDialogRef, useValue: { close: () => {} } },
            { provide: MAT_DIALOG_DATA, useValue: DIALOG_DATA },
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(PasswordDialog);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the password away from browser text assistance', () => {
      const password = fixture.nativeElement.querySelector('#password');
      expect(password.getAttribute('type')).toBe('text');
      expect(password.getAttribute('spellcheck')).toBe('false');
      expect(password.getAttribute('autocorrect')).toBe('off');
      expect(password.getAttribute('autocapitalize')).toBe('off');
      expect(password.getAttribute('autocomplete')).toBe('new-password');
   });

   it('keeps the hint away from browser text assistance', () => {
      const hint = fixture.nativeElement.querySelector('#hint');
      expect(hint.getAttribute('spellcheck')).toBe('false');
      expect(hint.getAttribute('autocomplete')).toBe('off');
      expect(hint.getAttribute('autocorrect')).toBe('off');
      expect(hint.getAttribute('autocapitalize')).toBe('off');
   });
});
