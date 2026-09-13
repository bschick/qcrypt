import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoAssistDirective } from './noassist.directive';

@Component({
   template: `
      <textarea id="words" noAssist></textarea>
      <input id="password" noAssist autocomplete="new-password" />
   `,
   imports: [NoAssistDirective],
})
class HostComponent {}

describe('NoAssistDirective', () => {
   let fixture: ComponentFixture<HostComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [HostComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(HostComponent);
      fixture.detectChanges();
   });

   it('turns off spellcheck, autocomplete, autocorrect, and autocapitalize', () => {
      const words = fixture.nativeElement.querySelector('#words');
      expect(words.getAttribute('spellcheck')).toBe('false');
      expect(words.getAttribute('autocomplete')).toBe('off');
      expect(words.getAttribute('autocorrect')).toBe('off');
      expect(words.getAttribute('autocapitalize')).toBe('off');
   });

   // Grammarly reads editable fields and does not treat spellcheck="false" as an opt out
   it('opts out of Grammarly', () => {
      const words = fixture.nativeElement.querySelector('#words');
      expect(words.getAttribute('data-gramm')).toBe('false');
   });

   it('keeps an autocomplete value the element sets for itself', () => {
      const password = fixture.nativeElement.querySelector('#password');
      expect(password.getAttribute('autocomplete')).toBe('new-password');
      expect(password.getAttribute('spellcheck')).toBe('false');
      expect(password.getAttribute('autocorrect')).toBe('off');
      expect(password.getAttribute('autocapitalize')).toBe('off');
   });
});
