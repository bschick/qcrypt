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
import { showRecoveryGuard } from './showrecovery/showrecovery.guard';
import { cmdlineGuard } from './cmdline/cmdline.guard';
import { coreGuard } from './core/core.guard';
import { welcomeGuard } from './welcome/welcome.guard';

export const routes: Routes = [
   { path: 'welcome', loadComponent: () => import('./welcome/welcome.component').then(m => m.WelcomeComponent), canActivate: [welcomeGuard] },
   { path: 'newuser', loadComponent: () => import('./newuser/newuser.component').then(m => m.NewUserComponent) },
   { path: 'showrecovery', loadComponent: () => import('./showrecovery/showrecovery.component').then(m => m.ShowRecoveryComponent), canActivate: [showRecoveryGuard] },
   { path: 'recovery', loadComponent: () => import('./recovery/recovery.component').then(m => m.RecoveryComponent) },
   { path: 'recovery2', loadComponent: () => import('./recovery2/recovery2.component').then(m => m.Recovery2Component) },
   { path: 'cmdline', loadComponent: () => import('./cmdline/cmdline.component').then(m => m.CmdLineComponent), canActivate: [cmdlineGuard] },
   { path: 'help', loadChildren: () => import('./help/help.routes').then(m => m.helpRoutes) },
   { path: '', component: CoreComponent, canActivate: [coreGuard] },
   { path: '**', redirectTo: '', pathMatch: 'full' },
];
