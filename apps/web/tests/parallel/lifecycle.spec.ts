import { test } from '@playwright/test';
import { lifecycleSuite } from './lifecycle.suite';

test.describe('lifecycle (no-PRF)', () => {
  lifecycleSuite(false);
});
