/* MIT License

Copyright (c) 2026 Brad Schick

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
import { Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { CopyrightComponent } from '../../ui/copyright/copyright.component';

@Component({
   selector: 'app-protocol6',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol6.component.html',
   styleUrl: './protocol.component.scss',
})
export class Protocol6Component {
   private readonly _dialog = inject(MatDialog);

   protected openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'flow-dialog',
   templateUrl: './flow-dialog.html',
   styleUrl: './protocol.component.scss',
   imports: [MatDialogModule, MatIconModule, MatTooltipModule, MatButtonModule],
})
export class FlowDialog {
   protected readonly flowImage = inject<string>(MAT_DIALOG_DATA);
}
