import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Rebuilds protocol8.pdf, the protocol page's stanza images, and their sizes in protocol8.component.html from
// main.tex, in the image that Containerfile defines. With --check, rebuilds and verifies the committed files match,
// without writing them.

const IMAGE = 'qcrypt-protocol';
// Rootless Podman needs no daemon or docker group membership, so it is used when installed
const ENGINE = spawnSync('podman', ['--version']).error ? 'docker' : 'podman';

// The page shows each image at half its pixel size, so 255 PPI displays at 127.5 CSS pixels per inch
const PPI = 255;
// Cairo draws thinner strokes than macOS, which darkens text stems. Growing each outline by one pixel at 4x, then
// scaling down, matches the macOS stroke weight.
const OVERSAMPLE = 4;
// Wider than the widest stanza (388pt) plus the symbols that overflow the 5mm column of the variable tables
const CROP_WIDTH_PT = 420;
// Glyphs reach slightly above a stanza's first line and below its last baseline
const CROP_TOP_PAD_PT = 4;
const CROP_BOTTOM_PAD_PT = 6;

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const protocolDir = path.join(repoRoot, 'apps/web/scripts/protocol');
// The 1020 PPI renders are large and /tmp may be in RAM, so the build uses this git-ignored directory
const buildDir = path.join(protocolDir, 'build');
const texPath = path.join(repoRoot, 'apps/web/src/assets-src/main.tex');
const htmlPath = path.join(repoRoot, 'apps/web/src/app/help/protocol/protocol8.component.html');
const assetsDir = path.join(repoRoot, 'apps/web/src/assets');
const pdfPath = path.join(assetsDir, 'protocol8.pdf');
const check = process.argv.includes('--check');

const relative = (file) => path.relative(repoRoot, file);

// Omits the creation date and trailer ID, so a rebuild of unchanged source is byte-identical
const DETERMINISTIC_PDF = '\\pdfinfoomitdate=1\\pdftrailerid{}\\pdfsuppressptexinfo=-1\n';

const STANZA_ENV = `   \\noindent\\hspace*{\\parindent}\\begin{minipage}{\\stanzabox}}
  {\\end{minipage}\\par\\addvspace{\\stanzagap}}`;

// The copy that the images are cut from:
// - no paragraph indent, as on the protocol page;
// - each title keeps its space but draws nothing;
// - each stanza writes its page, its top and bottom, and the page height to images.pos.
function imageSource(tex) {
   const replace = (text, from, to) => {
      if (text.split(from).length !== 2) {
         throw new Error(`protocol: expected exactly one "${from.split('\n')[0]}" in ${relative(texPath)}`);
      }
      return text.replace(from, to);
   };
   let source = replace(tex, '\\setlength\\parindent{20pt}', '\\setlength\\parindent{0pt}');
   source = replace(
      source,
      STANZA_ENV,
      `   \\stepcounter{stz}%
   \\noindent\\hspace*{\\parindent}\\begin{minipage}{\\stanzabox}\\posmark{S}}
  {\\par\\posmark{E}\\end{minipage}\\par\\addvspace{\\stanzagap}}`,
   );
   source = replace(
      source,
      '\\newlength{\\stanzabox}',
      `\\newlength{\\stanzabox}
\\newwrite\\posfile
\\immediate\\openout\\posfile=\\jobname.pos
\\newcounter{stz}
\\newcommand{\\posmark}[1]{\\pdfsavepos\\begingroup\\edef\\x{\\endgroup\\noexpand\\write\\noexpand\\posfile{#1 \\thestz\\space \\noexpand\\thepage\\space \\noexpand\\the\\noexpand\\pdflastypos\\space \\noexpand\\the\\noexpand\\pdfpageheight}}\\x}
\\let\\origunderline\\underline
\\renewcommand{\\underline}[1]{\\phantom{\\origunderline{#1}}}`,
   );
   return source;
}

function runInImage(status, script) {
   console.log(`protocol: ${status}`);
   const runArgs = [
      'run',
      '--rm',
      // Rootless Podman runs the container's root as the invoking user, so only Docker needs --user
      ...(ENGINE === 'docker' ? ['--user', `${process.getuid()}:${process.getgid()}`] : []),
      '-e',
      'HOME=/tmp',
      '--network',
      'none',
      '-v',
      `${buildDir}:/work`,
      '-w',
      '/work',
      IMAGE,
      'bash',
      '-c',
      `set -euo pipefail\n${script}`,
   ];
   const result = spawnSync(ENGINE, runArgs, { stdio: 'inherit' });
   if (result.error) {
      throw result.error;
   }
   if (result.status !== 0) {
      for (const log of ['publish.log', 'images.log']) {
         const logPath = path.join(buildDir, log);
         if (fs.existsSync(logPath)) {
            console.error(`--- last lines of ${relative(logPath)}`);
            console.error(fs.readFileSync(logPath, 'utf8').split('\n').slice(-30).join('\n'));
         }
      }
      throw new Error(`protocol: ${status} in ${IMAGE} exited with status ${result.status}`);
   }
}

// Stanza titles from main.tex and image names from the page, paired in order. Titles are compared as letters and
// digits only, since the TeX and HTML markup around them differ.
function pairImages(tex, html) {
   const comparable = (text) =>
      text
         .replace(/\\[A-Za-z]+/g, '')
         .replace(/<[^>]*>/g, '')
         .replace(/[^A-Za-z0-9]/g, '');
   const titles = [...tex.matchAll(/\\underline\{(.*)\}\\\\/g)].map((match) => match[1]);
   const images = [...html.matchAll(/<h2>([\s\S]*?)<\/h2>\s*<img src="\/assets\/([\w]+\.png)"/g)].map((match) => ({
      title: match[1],
      name: match[2],
   }));
   if (titles.length !== images.length) {
      throw new Error(
         `protocol: main.tex has ${titles.length} stanza titles but the page shows ${images.length} images`,
      );
   }
   titles.forEach((title, index) => {
      if (comparable(title) !== comparable(images[index].title)) {
         throw new Error(
            `protocol: stanza ${index + 1} "${title}" does not match page heading "${images[index].title}"`,
         );
      }
   });
   return images.map((image) => image.name);
}

// Each stanza's crop in output pixels, from the marks written in points from the page bottom
function stanzaCrops() {
   const marks = new Map();
   for (const line of fs.readFileSync(path.join(buildDir, 'images.pos'), 'utf8').trim().split('\n')) {
      const [kind, stanza, page, ySp, pageHeight] = line.split(' ');
      const entry = marks.get(stanza) ?? { page: Number(page), pageHeightPt: Number.parseFloat(pageHeight) };
      entry[kind] = Number(ySp.replace('sp', '')) / 65536;
      marks.set(stanza, entry);
   }
   return [...marks.values()].map((mark) => {
      const toPixels = (points) => (points * PPI) / 72;
      const top = Math.floor(toPixels(mark.pageHeightPt - mark.S - CROP_TOP_PAD_PT));
      const bottom = Math.ceil(toPixels(mark.pageHeightPt - mark.E + CROP_BOTTOM_PAD_PT));
      return { page: mark.page, top, height: bottom - top, width: Math.ceil(toPixels(CROP_WIDTH_PT)) };
   });
}

function pngSize(content) {
   return { width: content.readUInt32BE(16), height: content.readUInt32BE(20) };
}

console.log(`protocol: building the ${ENGINE} image`);
const containerfile = fs.readFileSync(path.join(protocolDir, 'Containerfile'), 'utf8');
execFileSync(ENGINE, ['build', '-q', '-t', IMAGE, '-'], { input: containerfile, stdio: ['pipe', 'ignore', 'inherit'] });

const tex = fs.readFileSync(texPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const names = pairImages(tex, html);

fs.rmSync(buildDir, { recursive: true, force: true });
fs.mkdirSync(path.join(buildDir, 'raw'), { recursive: true });
fs.mkdirSync(path.join(buildDir, 'png'), { recursive: true });
fs.writeFileSync(path.join(buildDir, 'publish.tex'), DETERMINISTIC_PDF + tex);
fs.writeFileSync(path.join(buildDir, 'images.tex'), DETERMINISTIC_PDF + imageSource(tex));

const pdflatex = (job) => `pdflatex -interaction=nonstopmode -halt-on-error ${job}.tex > /dev/null`;
// Two passes each, so page references and saved positions settle
runInImage('typesetting', ['publish', 'images'].map((job) => `${pdflatex(job)} && ${pdflatex(job)}`).join('\n'));

const crops = stanzaCrops();
if (crops.length !== names.length) {
   throw new Error(`protocol: typesetting marked ${crops.length} stanzas but the page shows ${names.length} images`);
}
const renders = crops.map((crop, index) => {
   const raw = `raw/${index}`;
   const scaled = (value) => value * OVERSAMPLE;
   return [
      `pdftocairo -r ${PPI * OVERSAMPLE} -f ${crop.page} -l ${crop.page} -x 0 -y ${scaled(crop.top)}`,
      `-W ${scaled(crop.width)} -H ${scaled(crop.height)} -png -singlefile -transp images.pdf ${raw}`,
      `&& magick ${raw}.png -channel A -morphology Dilate Disk:1 +channel -scale ${100 / OVERSAMPLE}%`,
      `-trim +repage -strip -define png:exclude-chunk=date,time png/${names[index]}`,
   ].join(' ');
});
runInImage('rendering stanza images', [...renders, 'optipng -quiet png/*.png'].join('\n'));

const outputs = new Map([[pdfPath, fs.readFileSync(path.join(buildDir, 'publish.pdf'))]]);
let page = html;
for (const name of names) {
   const content = fs.readFileSync(path.join(buildDir, 'png', name));
   outputs.set(path.join(assetsDir, name), content);
   // The page shows each image at half its pixel size, rounding an odd pixel count up
   const { width, height } = pngSize(content);
   const tag = new RegExp(`(<img src="/assets/${name}" )width="\\d+" height="\\d+"`);
   page = page.replace(tag, `$1width="${Math.ceil(width / 2)}" height="${Math.ceil(height / 2)}"`);
}
outputs.set(htmlPath, Buffer.from(page));

const differ = [...outputs].filter(([file, content]) => !fs.existsSync(file) || !fs.readFileSync(file).equals(content));
if (check) {
   if (differ.length > 0) {
      console.error(`protocol check: a rebuild of ${relative(texPath)} does not match:`);
      console.error(differ.map(([file]) => `   ${relative(file)}`).join('\n'));
      process.exit(1);
   }
   console.log('protocol check: the committed PDF, images and image sizes match a rebuild');
} else {
   for (const [file, content] of differ) {
      fs.writeFileSync(file, content);
   }
   console.log(`protocol regenerated: ${differ.length} of ${outputs.size} files changed`);
   for (const [file] of differ) {
      console.log(`   ${relative(file)}`);
   }
}
