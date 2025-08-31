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
   Component, Output, Input, EventEmitter, ViewChild, ElementRef
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatInputModule } from '@angular/material/input';
import { FormsModule } from '@angular/forms';

import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';


@Component({
    selector: 'app-editable',
    imports: [CommonModule, MatInputModule, FormsModule,
        MatFormFieldModule, MatIconModule, MatButtonModule
    ],
    templateUrl: './editable.component.html',
    styleUrl: './editable.component.scss'
})
export class EditableComponent {

   @Input() minlength = '0';
   @Input() maxlength = '50';
   @Output() valueChanged = new EventEmitter<EditableComponent>();
   @ViewChild('editableInput', { static: true }) editInput!: ElementRef;
   public text = '';
   public readOnly = true;
   private _value = '';

   @Input() set value(value: string) {
      this._value = value;
      this.text = value;
   }

   get value(): string {
      return this._value;
   }

   onFocusOut() {
      if (this._value != this.text) {
         this._value = this.text;
         this.valueChanged.emit(this);
      }
      this.readOnly = true;
   }

   makeEditable() {
      this.readOnly = false;
   }

   cancelEdit(event: any) {
      if (!this.readOnly) {
         this.text = this._value;
         event.stopPropagation();
         this.editInput.nativeElement.blur();
      }
   }

   acceptEdit(event: any) {
      if (!this.readOnly) {
         event.stopPropagation();
         this.editInput.nativeElement.blur();
      }
   }
}
