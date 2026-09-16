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
   private readonly matIconRegistry = inject(MatIconRegistry);
   private readonly domSanitizer = inject(DomSanitizer);

   public version = environment.clientVersion;
   public copyright = environment.copyright;

   constructor() {
      this.matIconRegistry.addSvgIcon(
         'github',
         this.domSanitizer.bypassSecurityTrustResourceUrl('../assets/github-circle.svg'),
      );
   }
}
