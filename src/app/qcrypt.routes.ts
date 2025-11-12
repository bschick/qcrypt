/* MIT License

Copyright (c) 2025 Brad Schick

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
import { Routes } from '@angular/router';
import { CoreComponent } from './core/core.component';
import { WelcomeComponent } from './welcome/welcome.component';
import { NewUserComponent } from './newuser/newuser.component';
import { ShowRecoveryComponent } from './showrecovery/showrecovery.component';
import { showRecoveryGuard } from './showrecovery/showrecovery.guard';
import { SenderLinksComponent } from './senderlinks/senderlinks.component';
import { senderLinksGuard } from './senderlinks/senderlinks.guard';
import { RecoveryComponent } from './recovery/recovery.component';
import { Recovery2Component } from './recovery2/recovery2.component';
import { CmdLineComponent } from './cmdline/cmdline.component';
import { cmdlineGuard } from './cmdline/cmdline.guard';
import { OverviewComponent } from './help/overview/overview.component';
import { FaqsComponent } from './help/faqs/faqs.component';
import { ProtocolComponent, Protocol4Component, Protocol5Component, Protocol6Component } from './help/protocol/protocol.component';
import { coreGuard } from './core/core.guard';
import { welcomeGuard } from './welcome/welcome.guard';

export const routes: Routes = [
   { path: 'welcome', component: WelcomeComponent, canActivate: [welcomeGuard] },
   { path: 'newuser', component: NewUserComponent },
   { path: 'senderlinks', component: SenderLinksComponent, canActivate: [senderLinksGuard] },
   { path: 'showrecovery', component: ShowRecoveryComponent, canActivate: [showRecoveryGuard] },
   { path: 'recovery', component: RecoveryComponent },
   { path: 'recovery2', component: Recovery2Component },
   { path: 'cmdline', component: CmdLineComponent, canActivate: [cmdlineGuard] },
   { path: 'help/overview', component: OverviewComponent },
   { path: 'help/faqs', component: FaqsComponent },
   { path: 'help/protocol', component: Protocol6Component },
   { path: 'help/protocol1', component: ProtocolComponent },
   { path: 'help/protocol4', component: Protocol4Component },
   { path: 'help/protocol5', component: Protocol5Component },
   { path: 'help/protocol6', component: Protocol6Component },
   { path: 'help', redirectTo: 'help/faqs', pathMatch: 'full'},
   { path: '', component: CoreComponent, canActivate: [coreGuard] },
   { path: '**', redirectTo: '', pathMatch: 'full' },
];
