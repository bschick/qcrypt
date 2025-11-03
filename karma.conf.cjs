// Karma configuration file, see link for more information
// https://karma-runner.github.io/1.0/config/configuration-file.html
//import {readFileSync} from "fs"
const fs = require('fs')

module.exports = function (config) {
  config.set({
    autoWatch: true,
    singleRun: false,
    usePolling: true,
    basePath: '',
    frameworks: ['jasmine', '@angular-devkit/build-angular'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-coverage'),

    ],
    browserDisconnectTimeout: 10000,
    browserDisconnectTolerance: 2,
    client: {
      jasmine: {
        timeoutInterval: 30000
        // you can add configuration options for Jasmine here
        // the possible options are listed at https://jasmine.github.io/api/edge/Configuration.html
        // for example, you can disable the random execution with `random: false`
        // or set a specific seed with `seed: 4321`
      },
      clearContext: false // leave Jasmine Spec Runner output visible in browser
    },
    jasmineHtmlReporter: {
      suppressAll: true // removes the duplicated traces
    },
    coverageReporter: {
      dir: require('path').join(__dirname, './coverage/qcrypt'),
      subdir: '.',
      reporters: [
        { type: 'html' },
        { type: 'text-summary' }
      ]
    },
    reporters: ['progress', 'kjhtml'],
    browsers: [],
    restartOnFileChange: true,
    listenAddress: '0.0.0.0',
    hostname: 't1.quickcrypt.org',
    protocol: 'https:',
    httpsServerOptions: {
      key: fs.readFileSync('localssl/localhost.key', 'utf8'),
      cert: fs.readFileSync('localssl/localhost.crt', 'utf8')
    },
  });
};
