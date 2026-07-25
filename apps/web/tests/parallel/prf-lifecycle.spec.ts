import { test } from '@playwright/test';
import { lifecycleSuite } from './lifecycle.suite';

test.describe('lifecycle (PRF)', () => {
   lifecycleSuite(true);
});
