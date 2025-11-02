import pkg from '../../package.json';

export const environment = {
    production: false,
    host: 'https://t1.quickcrypt.org:4200',
    apiHost: 'https://test.quickcrypt.org',
    apiVersion: 'v1',
    clientVersion: pkg.version,
    copyright: pkg.copyright
};
