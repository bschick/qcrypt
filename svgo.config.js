// svgo.config.js
// Default optimization config for SVGs in this repo (currently used by the
// `svgo:flow` script for files under apps/web/src/assets/flow/).
//
// Picked up automatically by `svgo` from the working directory.

export default {
   multipass: true,
   plugins: [
      {
         name: 'preset-default',
         params: {
            overrides: {
               // Keep ids that downstream code references via [data-target]
               // (qc-clickable contract) and the directive's CSS selector.
               cleanupIds: false,
               // Off because it also normalises attribute values like
               // data-target="01" into "1", breaking the 2-char hex contract.
               cleanupNumericValues: false,
            },
         },
      },
   ],
};
