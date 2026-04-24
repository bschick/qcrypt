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
import { guardedImport } from '../reloader';

export const helpRoutes: Routes = [
   { path: 'overview', loadComponent: () => guardedImport(() => import('./overview/overview.component').then(m => m.OverviewComponent)) },
   { path: 'faqs', loadComponent: () => guardedImport(() => import('./faqs/faqs.component').then(m => m.FaqsComponent)) },
   { path: 'protocol', loadComponent: () => guardedImport(() => import('./protocol/protocol.component').then(m => m.Protocol6Component)) },
   { path: 'protocol1', loadComponent: () => guardedImport(() => import('./protocol/protocol.component').then(m => m.ProtocolComponent)) },
   { path: 'protocol4', loadComponent: () => guardedImport(() => import('./protocol/protocol.component').then(m => m.Protocol4Component)) },
   { path: 'protocol5', loadComponent: () => guardedImport(() => import('./protocol/protocol.component').then(m => m.Protocol5Component)) },
   { path: 'protocol6', loadComponent: () => guardedImport(() => import('./protocol/protocol.component').then(m => m.Protocol6Component)) },
   { path: '', redirectTo: 'faqs', pathMatch: 'full' },
];
