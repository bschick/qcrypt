import pkg from '../../package.json';

export const environment = {
    production: true,
    host: 'https://quickcrypt.org',
    apiHost: 'https://quickcrypt.org',
    apiVersion: 'v1',
    clientVersion: pkg.version,
    copyright: pkg.copyright
};