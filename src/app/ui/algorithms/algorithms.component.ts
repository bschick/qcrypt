import {
  Component, Output, Input, EventEmitter
} from '@angular/core';
import * as cc from '../../services/cipher.consts';
import { MatTableModule } from '@angular/material/table';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

export type LoopInfo = {
  loop: number;
  alg: string;
};

@Component({
  selector: 'app-algorithms',
  standalone: true,
  imports: [MatTableModule, MatButtonToggleModule, FormsModule, ReactiveFormsModule],
  templateUrl: './algorithms.component.html',
  styleUrl: './algorithms.component.scss'
})
export class AlgorithmsComponent {

  public loopCount = 1;
  public displayedColumns: string[] = ['loop', 'algorithm'];
  public loops: LoopInfo[] = [];
  private _allowedAlgs = Object.keys(cc.AlgInfo);
  private _defaultModes = ['X20-PLY'];
  @Output() modesChanged = new EventEmitter<string[]>();

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
        do {
          nextAlg = this._allowedAlgs[(Math.random() * this._allowedAlgs.length) | 0]
        } while (nextAlg == alg);
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
    this.modesChanged.emit(this._defaultModes);
  }

  algDescription(alg: string): string {
    return cc.AlgInfo[alg]['description'] as string;
  }

}
