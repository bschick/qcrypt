import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CoprightComponent } from "../../ui/copright/copright.component";

@Component({
    selector: 'app-overview',
    templateUrl: './overview.component.html',
    styleUrl: './overview.component.scss',
    imports: [RouterLink, CoprightComponent]
})
export class OverviewComponent {

}
