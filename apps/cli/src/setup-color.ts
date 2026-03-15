// Must be imported before @inquirer/prompts so that styleText's
// color detection (which caches FORCE_COLOR at first call) sees
// these values. When --nocolor is passed, force color off.
// Otherwise, when stdout is redirected, default color on so that
// output written to the real terminal via reopened /dev/tty is styled.
if (process.argv.includes('--nocolor')) {
   process.env.FORCE_COLOR = '0';
   process.env.NO_COLOR = '1';
} else if (!process.stdout.isTTY) {
   process.env.FORCE_COLOR ??= '1';
}
