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
import { Component, ChangeDetectionStrategy, computed, input, model } from '@angular/core';
import { Ciphers } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import { MatTableModule } from '@angular/material/table';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { FormsModule } from '@angular/forms';

export function fillModes(modes: cc.CipherAlgs[], count: number): cc.CipherAlgs[] {
   const allowed = Ciphers.algs();
   const filled: cc.CipherAlgs[] = [modes[0] || 'X20-PLY'];
   for (let i = 1; i < count; i++) {
      const defaultIndex = (allowed.indexOf(filled[i - 1]) + 1) % allowed.length;
      filled.push(modes[i] || allowed[defaultIndex]);
   }
   return filled;
}

@Component({
   selector: 'app-algorithms',
   imports: [MatTableModule, MatButtonToggleModule, FormsModule],
   templateUrl: './algorithms.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './algorithms.component.scss',
})
export class AlgorithmsComponent {
   // May contain more entries than the current loop count
   readonly modes = model<cc.CipherAlgs[]>(['X20-PLY']);
   readonly count = input(1);

   private readonly _loopCount = computed(() => Math.max(1, this.count()));
   protected readonly filledModes = computed(() => fillModes(this.modes(), this._loopCount()));
   protected readonly loops = computed(() => Array.from({ length: this._loopCount() }, (_unused, index) => index + 1));
   protected readonly displayedColumns = computed(() =>
      this._loopCount() > 1 ? ['loop', 'algorithm'] : ['algorithm'],
   );

   protected onAlgorithmChange(loop: number, alg: cc.CipherAlgs): void {
      const modes = [...this.filledModes(), ...this.modes().slice(this._loopCount())];
      modes[loop - 1] = alg;
      this.modes.set(modes);
   }

   algDescription(alg: string): string {
      return Ciphers.algDescription(alg);
   }
}
