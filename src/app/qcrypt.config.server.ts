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
import { mergeApplicationConfig, ApplicationConfig } from '@angular/core';
//import { mergeApplicationConfig, ApplicationConfig, CSP_NONCE } from '@angular/core';
import { provideServerRendering } from '@angular/platform-server';
import { appConfig } from './qcrypt.config';

//const nonce = crypto.getRandomValues(new Uint8Array(16));
/*,{
      provide: CSP_NONCE,
      useValue: nonce
    }*/

const serverConfig: ApplicationConfig = {
   providers: [
      provideServerRendering(),
   ]
};

export const config = mergeApplicationConfig(appConfig, serverConfig);
