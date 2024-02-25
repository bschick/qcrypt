import { TestBed } from '@angular/core/testing';
import { CanActivateFn } from '@angular/router';

import { coreGuard } from './core.guard';

describe('coreGuard', () => {
  const executeGuard: CanActivateFn = (...guardParameters) => 
      TestBed.runInInjectionContext(() => coreGuard(...guardParameters));

  beforeEach(() => {
    TestBed.configureTestingModule({});
  });

  it('should be created', () => {
    expect(executeGuard).toBeTruthy();
  });
});
