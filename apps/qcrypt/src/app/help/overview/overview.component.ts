import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CopyrightComponent } from "../../ui/copyright/copyright.component";
import { environment } from '../../../environments/environment';

@Component({
    selector: 'app-overview',
    templateUrl: './overview.component.html',
    styleUrl: './overview.component.scss',
    imports: [RouterLink, CopyrightComponent]
})
export class OverviewComponent {
    public version = environment.clientVersion;
    public copyright = environment.copyright;
}
