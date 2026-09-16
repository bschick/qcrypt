import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { DomSanitizer } from '@angular/platform-browser';
import { CopyrightComponent } from '../../ui/copyright/copyright.component';
import { environment } from '../../../environments/environment';

@Component({
   selector: 'app-overview',
   templateUrl: './overview.component.html',
   styleUrl: './overview.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [RouterLink, MatButtonModule, MatIconModule, MatTooltipModule, CopyrightComponent],
})
export class OverviewComponent {
   private readonly _matIconRegistry = inject(MatIconRegistry);
   private readonly _domSanitizer = inject(DomSanitizer);

   public version = environment.clientVersion;
   public copyright = environment.copyright;

   constructor() {
      this._matIconRegistry.addSvgIcon(
         'github',
         this._domSanitizer.bypassSecurityTrustResourceUrl('../assets/github-circle.svg'),
      );
   }
}
