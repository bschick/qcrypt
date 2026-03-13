import * as fs from 'fs';
import * as url from 'url';
import * as esbuild from 'esbuild';

const importMetaPlugin = {
  name: 'import-meta-plugin',
  setup(build) {
    build.onLoad({ filter: /\.s?m?js$/ }, async (args) => {
      let contents = await fs.promises.readFile(args.path, 'utf8');
      if (contents.includes('import.meta.url')) {
        // use an inline replacement to grab the true global NodeJS require from the process to bypass ESBuild closures entirely
        contents = contents.replace(/import\.meta\.url/g, "(process.mainModule.require('url').pathToFileURL(__filename).href)");
      }
      return { contents, loader: 'js' };
    });
  },
};

esbuild.build({
  entryPoints: ['apps/cli/src/main.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'node',
  target: 'es2022',
  outfile: 'dist/cli/qcrypt.cjs',
  tsconfig: 'tsconfig.base.json',
  plugins: [importMetaPlugin],
}).catch(() => process.exit(1));
