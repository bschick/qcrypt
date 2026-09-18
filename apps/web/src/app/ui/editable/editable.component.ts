/* MIT License

Copyright (c) 2024 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */
import {
   Component,
   ElementRef,
   ChangeDetectionStrategy,
   effect,
   input,
   model,
   output,
   signal,
   viewChild,
} from '@angular/core';

import { MatInputModule } from '@angular/material/input';
import { FormsModule } from '@angular/forms';

import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { NoAssistDirective } from '../noassist.directive';

@Component({
   selector: 'app-editable',
   imports: [MatInputModule, FormsModule, MatFormFieldModule, MatIconModule, MatButtonModule, NoAssistDirective],
   templateUrl: './editable.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './editable.component.scss',
})
export class EditableComponent {
   readonly id = input('');
   readonly minlength = input('0');
   readonly maxlength = input('50');
   readonly readonly = input(false);
   readonly color = input('');
   readonly backgroundColor = input('');
   readonly value = model('');
   readonly valueChanged = output<EditableComponent>();
   readonly editInput = viewChild.required<ElementRef>('editableInput');

   protected readonly writing = signal(false);
   protected readonly text = signal('');

   constructor() {
      // A new committed value replaces whatever is being typed, including a rollback after a failed save
      effect(() => this.text.set(this.value()));
   }

   protected onFocusOut() {
      if (!this.readonly() && this.value() !== this.text()) {
         this.value.set(this.text());
         this.valueChanged.emit(this);
      }
      this.writing.set(false);
   }

   protected tryMakeEditable() {
      if (!this.readonly()) {
         this.writing.set(true);
      }
   }

   /* Blurring returns focus to whatever the surrounding focus trap prefers, so the key must
    * also be consumed or its default action fires against that newly focused element.
    */
   protected cancelEdit(event: Event) {
      event.stopPropagation();
      event.preventDefault();
      if (this.writing()) {
         this.text.set(this.value());
         this.editInput().nativeElement.blur();
      }
   }

   protected acceptEdit(event: Event) {
      event.stopPropagation();
      event.preventDefault();
      if (this.writing()) {
         this.editInput().nativeElement.blur();
      }
   }
}
