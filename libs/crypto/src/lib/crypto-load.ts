import sodium from 'libsodium-wrappers';
import { loadCrux, type Crux } from './crux/load';

export type Sodium = typeof sodium;
export type { Crux };

export async function load(): Promise<{ sodium: Sodium; crux: Crux }> {
   const [, crux] = await Promise.all([sodium.ready, loadCrux()]);
   return { sodium, crux };
}
