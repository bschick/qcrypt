import { Component } from '@angular/core';
import {MatInputModule} from '@angular/material/input';
import {MatFormFieldModule} from '@angular/material/form-field';
import {FormsModule} from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router } from '@angular/router';


@Component({
  selector: 'app-welcome',
  standalone: true,
  templateUrl: './welcome.component.html',
  styleUrl: './welcome.component.css',
  imports: [MatInputModule, MatFormFieldModule, FormsModule, MatButtonModule,
    MatProgressSpinnerModule
  ],

})
export class WelcomeComponent {

  public error: string = '';
  public showProgress: boolean = false;

  constructor(
    private auth: AuthenticatorService,
    private router: Router) {
  }

  async onClickExisting(event: any) {
    try {
      this.error = '';
      this.showProgress = true;
      await this.auth.passkeyLogin();
      this.router.navigateByUrl('/');
  } catch (err) {
      console.error(err);
      this.error = 'Passkey not found. Either try again or create a new passkey.';
  } finally {
      this.showProgress = false;
  }

  }

  onClickNew(event: any) {
    
  }

}
