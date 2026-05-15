import { shared } from './shared';

export const environment = {
    production: false,
    host: 'https://test.quickcrypt.org',
    // development and test will clobber each other's cookies because they both use
    // the same backend hostname of API calls. they are rejected at the server if
    // crossing front-end host URL, but the browser will still accept them.
    apiHost: 'https://test.quickcrypt.org',
    appPublicKey: 'public-key2',
    ...shared
};
