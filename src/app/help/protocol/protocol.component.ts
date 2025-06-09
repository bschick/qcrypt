import { CommonModule } from '@angular/common';
import { Component, Inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { CopyrightComponent } from "../../ui/copyright/copyright.component";


@Component({
    selector: 'app-protocol',
    imports: [MatTooltipModule, RouterLink, CopyrightComponent],
    templateUrl: './protocol.component.html',
    styleUrl: './protocol.component.scss'
})
export class ProtocolComponent {

   constructor(private dialog: MatDialog){
   }

   openFlowImage(flowImage:string) {
      this.dialog.open(FlowDialog, { data: flowImage });
   }
}

@Component({
    selector: 'app-protocol4',
    imports: [MatTooltipModule, RouterLink, CopyrightComponent],
    templateUrl: './protocol4.component.html',
    styleUrl: './protocol.component.scss'
})
export class Protocol4Component {

   constructor(private dialog: MatDialog){
   }

   openFlowImage(flowImage:string) {
      this.dialog.open(FlowDialog, { data: flowImage });
   }
}


@Component({
    selector: 'flow-dialog',
    templateUrl: './flow-dialog.html',
    styleUrl: './protocol.component.scss',
    imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
        MatButtonModule]
})
export class FlowDialog {

   public flowImage: string;
   public zoomed = true;

   constructor(
      public dialogRef: MatDialogRef<FlowDialog>,
      @Inject(MAT_DIALOG_DATA) public flowData: string
   ) {
      this.flowImage = flowData;
   }

}