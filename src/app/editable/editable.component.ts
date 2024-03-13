import {
   Component, OnInit, Output, Input, EventEmitter, ViewChild, ElementRef
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatInputModule } from '@angular/material/input';
import { FormsModule } from '@angular/forms';

import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';


@Component({
   selector: 'app-editable',
   standalone: true,
   imports: [CommonModule, MatInputModule, FormsModule,
      MatFormFieldModule, MatIconModule, MatButtonModule
   ],
   templateUrl: './editable.component.html',
   styleUrl: './editable.component.scss'
})
export class EditableComponent implements OnInit {

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

   constructor(
   ) {
   }

   ngOnInit() {
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
