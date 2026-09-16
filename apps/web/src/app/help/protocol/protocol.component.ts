import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { CopyrightComponent } from '../../ui/copyright/copyright.component';

@Component({
   selector: 'app-protocol',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class ProtocolComponent {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'app-protocol4',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol4.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class Protocol4Component {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'app-protocol5',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol5.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class Protocol5Component {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'app-protocol6',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol6.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class Protocol6Component {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'app-protocol7',
   imports: [MatTooltipModule, CopyrightComponent],
   templateUrl: './protocol7.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class Protocol7Component {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'app-protocol8',
   imports: [MatTooltipModule, RouterLink, CopyrightComponent],
   templateUrl: './protocol8.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './protocol.component.scss',
})
export class Protocol8Component {
   private readonly _dialog = inject(MatDialog);

   openFlowImage(flowImage: string) {
      this._dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
   selector: 'flow-dialog',
   templateUrl: './flow-dialog.html',
   styleUrl: './protocol.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatDialogModule, MatIconModule, MatTooltipModule, MatButtonModule],
})
export class FlowDialog {
   private readonly _flowData = inject<string>(MAT_DIALOG_DATA);

   public flowImage: string;
   public zoomed = true;

   constructor() {
      this.flowImage = this._flowData;
   }
}
