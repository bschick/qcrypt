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
   Component, Output, Input, EventEmitter
} from '@angular/core';
import * as cc from '@qcrypt/crypto/consts';
import { MatTableModule } from '@angular/material/table';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { FormsModule } from '@angular/forms';

export type LoopInfo = {
   loop: number;
   alg: string;
};

@Component({
   selector: 'app-algorithms',
   imports: [MatTableModule, MatButtonToggleModule, FormsModule],
   templateUrl: './algorithms.component.html',
   styleUrl: './algorithms.component.scss'
})
export class AlgorithmsComponent {

   public loopCount = 1;
   public displayedColumns: string[] = ['loop', 'algorithm'];
   public loops: LoopInfo[] = [];
   private _allowedAlgs = Object.keys(cc.AlgInfo);
   private _defaultModes = ['X20-PLY'];
   @Output() modesChange = new EventEmitter<string[]>();

   @Input() set count(count: number) {

      this.loopCount = Math.max(1, count);

      this.displayedColumns = ['algorithm'];
      if (this.loopCount > 1) {
         this.displayedColumns.unshift('loop');
      }

      this.loops = [];
      let nextAlg = this._defaultModes[0] || 'X20-PLY';

      for (let l = 0; l < this.loopCount; l++) {
         const alg = nextAlg;
         this.loops.push({
            loop: l + 1,
            alg: alg
         });

         this._defaultModes[l] = alg;

         // Use a default for next alg if we have one, else randomly pick
         nextAlg = this._defaultModes[l + 1]
         if (!nextAlg) {
            const idx = this._allowedAlgs.indexOf(alg);
            nextAlg = this._allowedAlgs[(idx + 1) % this._allowedAlgs.length];
         }
      }
   }

   @Input() set modes(modes: string[]) {
      this._defaultModes = modes;
   }

   get modes(): string[] {
      // note that this returns all defaults, even when larger than
      // the current loopCount
      return this._defaultModes;
   }

   onAlgorithmChange(event: any, loop: number): void {
      this._defaultModes[loop - 1] = event.value;
      this.modesChange.emit(this._defaultModes);
   }

   algDescription(alg: string): string {
      return cc.AlgInfo[alg]['description'] as string;
   }

}
