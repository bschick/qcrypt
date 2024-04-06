import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
   selector: 'app-overview',
   standalone: true,
   templateUrl: './overview.component.html',
   styleUrl: './overview.component.scss',
   imports: [RouterLink
   ],
})
export class OverviewComponent {

}
