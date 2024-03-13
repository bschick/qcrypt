import { TestBed } from '@angular/core/testing';

import { ZxcvbnOptionsService } from './zxcvbn-options.service';

describe('ZxcvbnOptionsService', () => {
   let service: ZxcvbnOptionsService;

   beforeEach(() => {
      TestBed.configureTestingModule({});
      service = TestBed.inject(ZxcvbnOptionsService);
   });

   it('should be created', () => {
      expect(service).toBeTruthy();
   });
});
