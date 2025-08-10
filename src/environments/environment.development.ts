import pkg from '../../package.json';

export const environment = {
    production: false,
    domain: 'https://test.quickcrypt.org',
    apiVersion: 'v1',
    clientVersion: pkg.version,
    copyright: pkg.copyright
};
