// Must be imported before @inquirer/prompts so that styleText's
// color detection (which caches FORCE_COLOR at first call) sees
// this value. Without it, redirected stdout causes isTTY=false
// and all ANSI styling is stripped — even for output written to
// the real terminal via reopened /dev/tty.
if (!process.stdout.isTTY) {
   process.env.FORCE_COLOR ??= '1';
}
