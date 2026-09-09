import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from 'vitest';
import { execSync, spawn, spawnSync, type SpawnSyncReturns } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';

describe('CLI App', () => {
   const cliPath = path.resolve(__dirname, '../../../dist/cli/qcrypt.cjs');
   const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qcrypt-cli-'));
   const userCred = '_sHEi_YNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
   const wrongCred = 'AAAAAYNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
   const clearText = 'This is a secret message to test the CLI.';

   const inFilePath = path.resolve(tmpDir, 'test-in.txt');
   const encryptedFilePath = path.resolve(tmpDir, 'test-enc.bin');
   const decryptedFilePath = path.resolve(tmpDir, 'test-dec.txt');
   const infoFilePath = path.resolve(tmpDir, 'test-info.txt');

   // A contention/OOM kill exits via signal with null status and empty stderr,
   // so log signal and the spawn error too — stdout/stderr alone wouldn't explain it.
   const logCliFailure = (args: string[], result: SpawnSyncReturns<string | Buffer>): void => {
      const text = (value: string | Buffer | null) => (value == null ? '' : value.toString());
      console.error(
         `Command failed: node ${cliPath} ${args.join(' ')}\n` +
            `status: ${result.status}, signal: ${result.signal}, error: ${result.error ?? 'none'}\n` +
            `stdout: ${text(result.stdout)}\nstderr: ${text(result.stderr)}`,
      );
   };

   const execCli = (args: string[], input?: string | Buffer): SpawnSyncReturns<string> => {
      const result = spawnSync('node', [cliPath, ...args], {
         encoding: 'utf-8',
         input: input ?? '',
      });
      if (result.status !== 0) {
         logCliFailure(args, result);
      }
      return result;
   };

   // Returns stdout/stderr as raw Buffers so binary ciphertext survives intact;
   // utf-8 decoding would corrupt the bytes.
   const execCliBin = (args: string[], input?: string | Buffer): SpawnSyncReturns<Buffer> => {
      const result = spawnSync('node', [cliPath, ...args], {
         encoding: null,
         input: input ?? '',
      });
      if (result.status !== 0) {
         logCliFailure(args, result);
      }
      return result;
   };

   beforeAll(() => {
      if (!process.env['SKIP_BUILD']) {
         console.log('Building CLI before running tests...');
         execSync('pnpm nx build cli', { stdio: 'inherit' });
      }
      fs.writeFileSync(inFilePath, clearText, 'utf-8');
   });

   afterAll(() => {
      try {
         fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch (err) {
         console.error(`Failed to clean up ${tmpDir}:`, err);
      }
   });

   describe('enc command', () => {
      it('should throw error when provided invalid cred length', () => {
         const result = execCli(
            ['enc', '--cred', 'SHORT', '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('Invalid character');
      });

      it('should throw error for non-digit iters', () => {
         const result = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', 'NOTADIGIT', '--pwds', 'pass'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('iters is not a valid number');
      });

      it('should throw error for non-digit loops', () => {
         const result = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', 'NOTADIGIT', '--pwds', 'pass'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('loops is not a valid number');
      });

      it('should throw error if more algs than loops', () => {
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '1',
               '--algs',
               'AES-GCM',
               'X20-PLY',
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('2 algs provided for 1 loops');
      });

      it('should throw error if more pwds than loops', () => {
         const result = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '1', '--pwds', 'pass1', 'pass2'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('2 pwds provided for 1 loops');
      });

      it('should throw error if more hints than loops', () => {
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '1',
               '--pwds',
               'pass',
               '--hints',
               'h1',
               'h2',
            ],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('2 hints provided for 1 loops');
      });

      it('should store hint provided via --hints in cipher info', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-hint.bin');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               tmpEnc,
               '--pwds',
               'pass',
               '--hints',
               'my hint',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const info = execCli(['info', '--cred', userCred, '--silent', '--infile', tmpEnc]);
         expect(info.status).toBe(0);
         expect(info.stdout).toContain('Password Hint     : my hint');
         fs.unlinkSync(tmpEnc);
      });

      it('should align hints by position with pwds across loops', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-multi-hint.bin');
         // hints[0] pairs with pwds[0] (loop 1, innermost); hints[1] with pwds[1] (loop 2, outermost).
         // info reveals only the outermost layer's hint.
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '2',
               '--outfile',
               tmpEnc,
               '--pwds',
               'p1',
               'p2',
               '--hints',
               'inner hint',
               'outer hint',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const info = execCli(['info', '--cred', userCred, '--silent', '--infile', tmpEnc]);
         expect(info.status).toBe(0);
         expect(info.stdout).toContain('Password Hint     : outer hint');
         expect(info.stdout).not.toContain('inner hint');
         fs.unlinkSync(tmpEnc);
      });

      it('should accept fewer hints than pwds', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-partial-hint.bin');
         // hints only covers loop 1; loop 2 (outermost) gets no hint
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '2',
               '--outfile',
               tmpEnc,
               '--pwds',
               'p1',
               'p2',
               '--hints',
               'inner only',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const info = execCli(['info', '--cred', userCred, '--silent', '--infile', tmpEnc]);
         expect(info.status).toBe(0);
         expect(info.stdout).not.toContain('inner only');
         fs.unlinkSync(tmpEnc);
      });

      it('should roundtrip encrypt/decrypt with --hints', () => {
         const rtEnc = path.resolve(tmpDir, 'test-rt-hint.bin');
         const rtDec = path.resolve(tmpDir, 'test-rt-hint.txt');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               rtEnc,
               '--pwds',
               'pass',
               '--hints',
               'roundtrip hint',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const dec = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
            '--pwds',
            'pass',
         ]);
         expect(dec.status).toBe(0);
         expect(fs.readFileSync(rtDec, 'utf-8')).toBe(clearText);
         fs.unlinkSync(rtEnc);
         fs.unlinkSync(rtDec);
      });

      it('should reject invalid alg options', () => {
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '1',
               '--algs',
               'FAKE-CIPHER',
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('Unsupported cipher mode: FAKE-CIPHER.');
      });

      it('should reject --infile and text together', () => {
         const result = execCli([
            'enc',
            clearText,
            '--cred',
            userCred,
            '--silent',
            '--iters',
            '1000000',
            '--infile',
            inFilePath,
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('infile');
      });

      it('should accept lowercase algorithm names', () => {
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--algs',
               'aes-gcm',
               '--outfile',
               encryptedFilePath,
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(result.status).toBe(0);
         expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
      });

      it('should encrypt successfully with piped clear text', () => {
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               encryptedFilePath,
               '--force',
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(result.status).toBe(0);
         expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
      });

      it('should handle debug flag properly', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-debug.bin');
         const secretPwd = 'SUPER_SECRET_PASSWORD_1';
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--debug',
               '--iters',
               '1000000',
               '--algs',
               'AES-GCM',
               '--outfile',
               tmpEnc,
               '--pwds',
               secretPwd,
            ],
            clearText,
         );
         expect(result.status).toBe(0);
         expect(result.stderr).toContain('args ->'); // debug output goes to stderr

         // Debug output is routinely pasted into bug reports and captured by CI logs
         expect(result.stderr).not.toContain(userCred);
         expect(result.stderr).not.toContain(secretPwd);
         fs.unlinkSync(tmpEnc);
      });

      it('should encrypt using files', () => {
         const result = execCli([
            'enc',
            '--cred',
            userCred,
            '--silent',
            '--iters',
            '1000000',
            '--infile',
            inFilePath,
            '--outfile',
            encryptedFilePath,
            '--force',
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(0);
         expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
      });

      it('should process extra layers and parameters', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-extra.bin');
         const result = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '2',
               '--algs',
               'AES-GCM',
               'X20-PLY',
               '--outfile',
               tmpEnc,
               '--pwds',
               'pass1',
               'pass2',
            ],
            clearText,
         );
         expect(result.status).toBe(0);
         expect(fs.statSync(tmpEnc).size).toBeGreaterThan(0);
         fs.unlinkSync(tmpEnc);
      });

      it.each([['AES-GCM'], ['X20-PLY'], ['AEGIS-256']])('should roundtrip encrypt/decrypt with %s', (alg) => {
         const rtEnc = path.resolve(tmpDir, `test-rt-${alg}.bin`);
         const rtDec = path.resolve(tmpDir, `test-rt-${alg}.txt`);
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--algs',
               alg,
               '--outfile',
               rtEnc,
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const dec = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
            '--pwds',
            'pass',
         ]);
         expect(dec.status).toBe(0);
         expect(fs.readFileSync(rtDec, 'utf-8')).toBe(clearText);
         fs.unlinkSync(rtEnc);
         fs.unlinkSync(rtDec);
      });

      it('should fail rather than report success on empty piped input', () => {
         const good = execCliBin(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(good.status).toBe(0);

         // Exiting 0 here reads as a successful encrypt of nothing
         const result = execCliBin(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'], '');
         expect(result.status).toBe(1);
         expect(result.stdout.length).toBe(0);
      });

      it('encrypts the text argument when nothing is piped in', () => {
         const enc = execCliBin(
            ['enc', 'text argument', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            '',
         );
         expect(enc.status).toBe(0);

         const dec = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass'], enc.stdout);
         expect(dec.status).toBe(0);
         expect(dec.stdout.trim()).toBe('text argument');
      });

      it('encrypts numeric looking text exactly as given', () => {
         const enc = execCliBin(
            ['enc', '1e3', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            '',
         );
         expect(enc.status).toBe(0);

         const dec = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass'], enc.stdout);
         expect(dec.status).toBe(0);
         expect(dec.stdout.trim()).toBe('1e3');
      });

      it('refuses a text argument together with piped input', () => {
         const result = execCli(
            ['enc', 'text argument', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(result.status).toBe(1);
      });
   });

   describe('dec command', () => {
      it('should throw error for invalid cred length on decrypt', () => {
         const result = execCli([
            'dec',
            '--cred',
            'SHORT',
            '--silent',
            '--infile',
            encryptedFilePath,
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(1);
      });

      it('should throw error when given wrong password', () => {
         const result = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--pwds',
            'WRONGPASS',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('decryption failed');
      });

      it('should decrypt successfully from file', () => {
         const result = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--outfile',
            decryptedFilePath,
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(0);
         expect(fs.readFileSync(decryptedFilePath, 'utf-8')).toBe(clearText);
      });

      it('should decrypt correctly with multiple passwords matching length', () => {
         const rtEnc = path.resolve(tmpDir, 'test-multi.bin');
         const rtDec = path.resolve(tmpDir, 'test-multi.txt');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '2',
               '--outfile',
               rtEnc,
               '--pwds',
               'A',
               'B',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const dec = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
            '--pwds',
            'B',
            'A',
         ]);
         expect(dec.status).toBe(0);
         expect(fs.readFileSync(rtDec, 'utf-8')).toBe(clearText);
         fs.unlinkSync(rtEnc);
         fs.unlinkSync(rtDec);
      });

      it('should decrypt using default command without dec keyword', () => {
         const result = execCli([
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--outfile',
            decryptedFilePath,
            '--force',
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(0);
         expect(fs.readFileSync(decryptedFilePath, 'utf-8')).toBe(clearText);
      });

      it('should fail with wrong credential of valid length', () => {
         const result = execCli([
            'dec',
            '--cred',
            wrongCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('decryption failed');
      });

      it('should fail when given fewer passwords than loops', () => {
         const rtEnc = path.resolve(tmpDir, 'test-fewpwds.bin');
         const rtDec = path.resolve(tmpDir, 'test-fewpwds.txt');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--loops',
               '2',
               '--outfile',
               rtEnc,
               '--pwds',
               'A',
               'B',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);

         const ok = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
            '--pwds',
            'B',
            'A',
         ]);
         expect(ok.status).toBe(0);

         const result = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
            '--force',
            '--pwds',
            'B',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('2 password(s) required in silent mode but 1 provided');

         fs.rmSync(rtEnc, { force: true });
         // Already removed by the failed decrypt
         fs.rmSync(rtDec, { force: true });
      });

      // Asserts bytes as well as exit code: a truncated decrypt that still exits 0
      // reads as success to an automation pipeline that then deletes the cipher text
      it('should round trip a multi-megabyte payload in silent mode', () => {
         const bigIn = path.resolve(tmpDir, 'test-big-in.bin');
         const bigEnc = path.resolve(tmpDir, 'test-big-enc.bin');
         const bigDec = path.resolve(tmpDir, 'test-big-dec.bin');

         const bigData = Buffer.alloc(2 * 1024 * 1024 + 1000);
         for (let pos = 0; pos < bigData.length; pos++) {
            bigData[pos] = pos % 251;
         }
         fs.writeFileSync(bigIn, bigData);

         const enc = execCli([
            'enc',
            '--cred',
            userCred,
            '--silent',
            '--iters',
            '1000000',
            '--infile',
            bigIn,
            '--outfile',
            bigEnc,
            '--pwds',
            'pass',
         ]);
         expect(enc.status).toBe(0);

         const dec = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            bigEnc,
            '--outfile',
            bigDec,
            '--pwds',
            'pass',
         ]);
         expect(dec.status).toBe(0);
         expect(fs.readFileSync(bigDec).equals(bigData)).toBe(true);

         fs.unlinkSync(bigIn);
         fs.unlinkSync(bigEnc);
         fs.unlinkSync(bigDec);
      });
   });

   describe('--credfile', () => {
      const credPath = path.resolve(tmpDir, 'test-credfile.txt');
      const encPath = path.resolve(tmpDir, 'test-credfile-enc.bin');

      afterEach(() => {
         fs.rmSync(credPath, { force: true });
         fs.rmSync(encPath, { force: true });
      });

      it('reads the credential from a file, ignoring a trailing newline', () => {
         // echo and most editors append one, so requiring an exact byte match would surprise
         fs.writeFileSync(credPath, `${userCred}\n`, 'utf-8');

         const enc = execCli(
            ['enc', '--credfile', credPath, '--silent', '--iters', '1000000', '--outfile', encPath, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const info = execCli(['info', '--cred', userCred, '--silent', '--infile', encPath]);
         expect(info.status).toBe(0);
      });

      it('never echoes the credential it read', () => {
         fs.writeFileSync(credPath, userCred, 'utf-8');

         const result = execCli(
            [
               'enc',
               '--credfile',
               credPath,
               '--debug',
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               encPath,
               '--pwds',
               'pass',
            ],
            clearText,
         );
         expect(result.status).toBe(0);
         expect(result.stderr).not.toContain(userCred);
         expect(result.stdout).not.toContain(userCred);
      });

      it('reports a missing credential file', () => {
         const result = execCli(
            ['enc', '--credfile', path.resolve(tmpDir, 'nope.txt'), '--silent', '--iters', '1000000', '--pwds', 'p'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('nope.txt');
      });

      it('rejects being combined with --cred', () => {
         fs.writeFileSync(credPath, userCred, 'utf-8');

         const result = execCli(
            ['enc', '--cred', userCred, '--credfile', credPath, '--silent', '--iters', '1000000', '--pwds', 'p'],
            clearText,
         );
         expect(result.status).toBe(1);
      });
   });

   describe('--outfile protection', () => {
      const outPath = path.resolve(tmpDir, 'test-outfile-guard.bin');
      const cipherPath = path.resolve(tmpDir, 'test-outfile-guard-cipher.bin');
      // Windows has no POSIX file modes and needs a privilege to create symlinks
      const skipOnWindows = process.platform === 'win32';
      // chmod does not restrict root, so a refusal cannot be observed
      const skipUnrestricted = skipOnWindows || process.getuid?.() === 0;

      beforeAll(() => {
         expect(encryptTo(cipherPath).status).toBe(0);
      });

      afterEach(() => {
         if (fs.existsSync(outPath)) {
            fs.unlinkSync(outPath);
         }
      });

      function decryptTo(target: string, password: string, extra: string[] = []): SpawnSyncReturns<string> {
         return execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            cipherPath,
            '--outfile',
            target,
            '--pwds',
            password,
            ...extra,
         ]);
      }

      function encryptTo(target: string, extra: string[] = []): SpawnSyncReturns<string> {
         return execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               target,
               '--pwds',
               'pass',
               ...extra,
            ],
            clearText,
         );
      }

      it.skipIf(skipOnWindows)('creates the output readable only by its owner', () => {
         expect(encryptTo(outPath).status).toBe(0);
         expect(fs.statSync(outPath).mode & 0o777).toBe(0o600);
      });

      it('refuses to overwrite an existing file and leaves it untouched', () => {
         fs.writeFileSync(outPath, 'do not clobber me', 'utf-8');

         const result = encryptTo(outPath);
         expect(result.status).toBe(1);
         expect(fs.readFileSync(outPath, 'utf-8')).toBe('do not clobber me');
      });

      it('overwrites an existing file when forced', () => {
         fs.writeFileSync(outPath, 'replace me', 'utf-8');

         expect(encryptTo(outPath, ['--force']).status).toBe(0);
         expect(fs.readFileSync(outPath, 'utf-8')).not.toBe('replace me');
      });

      it.skipIf(skipOnWindows)('restricts permissions when forced over a group and world readable file', () => {
         fs.writeFileSync(outPath, 'replace me', 'utf-8');
         fs.chmodSync(outPath, 0o644);

         expect(decryptTo(outPath, 'pass', ['--force']).status).toBe(0);
         expect(fs.readFileSync(outPath, 'utf-8')).toBe(clearText);
         expect(fs.statSync(outPath).mode & 0o777).toBe(0o600);
      });

      it.skipIf(skipOnWindows)('replaces a symlink destination rather than writing through it', () => {
         const linkTarget = path.resolve(tmpDir, 'test-outfile-guard-link-target.txt');
         fs.writeFileSync(linkTarget, 'not the destination', 'utf-8');
         fs.symlinkSync(linkTarget, outPath);

         expect(decryptTo(outPath, 'pass', ['--force']).status).toBe(0);
         expect(fs.readFileSync(linkTarget, 'utf-8')).toBe('not the destination');
         expect(fs.lstatSync(outPath).isSymbolicLink()).toBe(false);
         expect(fs.readFileSync(outPath, 'utf-8')).toBe(clearText);
         fs.unlinkSync(linkTarget);
      });

      it.skipIf(skipUnrestricted)('refuses a forced overwrite of a file the user cannot write', () => {
         fs.writeFileSync(outPath, 'protected original', 'utf-8');
         fs.chmodSync(outPath, 0o444);

         expect(decryptTo(outPath, 'pass', ['--force']).status).toBe(1);
         expect(fs.readFileSync(outPath, 'utf-8')).toBe('protected original');
      });

      it.skipIf(skipUnrestricted)('refuses a forced overwrite inside a directory the user cannot write', () => {
         const lockedDir = path.resolve(tmpDir, 'test-outfile-guard-locked');
         const target = path.resolve(lockedDir, 'target.txt');
         fs.mkdirSync(lockedDir);
         fs.writeFileSync(target, 'protected original', 'utf-8');
         fs.chmodSync(lockedDir, 0o555);

         try {
            expect(decryptTo(target, 'pass', ['--force']).status).toBe(1);
            expect(fs.readFileSync(target, 'utf-8')).toBe('protected original');
         } finally {
            fs.chmodSync(lockedDir, 0o755);
            fs.rmSync(lockedDir, { recursive: true, force: true });
         }
      });

      it.skipIf(skipOnWindows)('removes the output when interrupted by a signal', async () => {
         const pipePath = path.resolve(tmpDir, 'test-outfile-guard-pipe');
         fs.writeFileSync(outPath, 'do not destroy me', 'utf-8');
         execSync(`mkfifo '${pipePath}'`);
         const before = fs.readdirSync(tmpDir);
         const addedFiles = () => fs.readdirSync(tmpDir).filter((name) => !before.includes(name));
         // Holding a partial cipher in the pipe stalls the decrypt with its output already open
         const feeder = spawn('bash', ['-c', `{ head -c 100 '${cipherPath}'; sleep 30; } > '${pipePath}'`]);
         const decrypting = spawn('node', [
            cliPath,
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            pipePath,
            '--outfile',
            outPath,
            '--force',
            '--pwds',
            'pass',
         ]);

         try {
            await vi.waitFor(() => expect(addedFiles().length).toBe(1), { timeout: 10000 });
            decrypting.kill('SIGINT');
            await new Promise((resolve) => decrypting.once('exit', resolve));

            expect(addedFiles()).toEqual([]);
            expect(fs.readFileSync(outPath, 'utf-8')).toBe('do not destroy me');
         } finally {
            feeder.kill();
            decrypting.kill();
            fs.rmSync(pipePath, { force: true });
         }
      });

      it('leaves the destination intact when a forced command fails', () => {
         fs.writeFileSync(outPath, 'do not destroy me', 'utf-8');

         expect(decryptTo(outPath, 'WRONGPASS', ['--force']).status).toBe(1);
         expect(fs.readFileSync(outPath, 'utf-8')).toBe('do not destroy me');
      });

      it('leaves no output behind when the command fails', () => {
         expect(encryptTo(outPath).status).toBe(0);
         const cipherText = fs.readFileSync(outPath);
         fs.unlinkSync(outPath);

         const encPath = path.resolve(tmpDir, 'test-outfile-guard-enc.bin');
         fs.writeFileSync(encPath, cipherText);

         const result = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encPath,
            '--outfile',
            outPath,
            '--pwds',
            'WRONGPASS',
         ]);
         expect(result.status).toBe(1);
         // A zero byte leftover reads as a successful decrypt to whatever runs next
         expect(fs.existsSync(outPath)).toBe(false);
         fs.unlinkSync(encPath);
      });
   });

   describe('input formats', () => {
      it('should roundtrip with JSON cipher armor infile', () => {
         const binEnc = path.resolve(tmpDir, 'test-fmt-bin.bin');
         const jsonEnc = path.resolve(tmpDir, 'test-fmt.json');
         const dec = path.resolve(tmpDir, 'test-fmt-dec.txt');

         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const binData = fs.readFileSync(binEnc);
         const cipherArmor = JSON.stringify({ ct: Buffer.from(binData).toString('base64url') });
         fs.writeFileSync(jsonEnc, cipherArmor, 'utf-8');

         const result = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            jsonEnc,
            '--outfile',
            dec,
            '--pwds',
            'pass',
         ]);
         expect(result.status).toBe(0);
         expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

         fs.unlinkSync(binEnc);
         fs.unlinkSync(jsonEnc);
         fs.unlinkSync(dec);
      });

      it('should roundtrip with binary stdin', () => {
         const binEnc = path.resolve(tmpDir, 'test-stdin-bin.bin');
         const dec = path.resolve(tmpDir, 'test-stdin-bin-dec.txt');

         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const binData = fs.readFileSync(binEnc);
         const result = execCliBin(
            ['dec', '--cred', userCred, '--silent', '--outfile', dec, '--pwds', 'pass'],
            binData,
         );
         expect(result.status).toBe(0);
         expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

         fs.unlinkSync(binEnc);
         fs.unlinkSync(dec);
      });

      it('should roundtrip with JSON cipher armor stdin', () => {
         const binEnc = path.resolve(tmpDir, 'test-stdin-json.bin');
         const dec = path.resolve(tmpDir, 'test-stdin-json-dec.txt');

         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const binData = fs.readFileSync(binEnc);
         const cipherArmor = JSON.stringify({ ct: Buffer.from(binData).toString('base64url') });
         const result = execCli(
            ['dec', '--cred', userCred, '--silent', '--outfile', dec, '--pwds', 'pass'],
            cipherArmor,
         );
         expect(result.status).toBe(0);
         expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

         fs.unlinkSync(binEnc);
         fs.unlinkSync(dec);
      });

      it('should detect binary infile for info command', () => {
         const binEnc = path.resolve(tmpDir, 'test-info-bin.bin');
         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', binEnc]);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('Cipher and Mode');

         fs.unlinkSync(binEnc);
      });

      it('should detect JSON infile for info command', () => {
         const binEnc = path.resolve(tmpDir, 'test-info-json.bin');
         const jsonEnc = path.resolve(tmpDir, 'test-info.json');

         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);

         const binData = fs.readFileSync(binEnc);
         const cipherArmor = JSON.stringify({ ct: Buffer.from(binData).toString('base64url') });
         fs.writeFileSync(jsonEnc, cipherArmor, 'utf-8');

         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', jsonEnc]);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('Cipher and Mode');

         fs.unlinkSync(binEnc);
         fs.unlinkSync(jsonEnc);
      });

      it('should pipe enc output to info', () => {
         const enc = execCliBin(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);
         const result = execCli(['info', '--cred', userCred, '--silent'], enc.stdout);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('Cipher and Mode');
         expect(result.stdout).toContain('Loops');
      });

      it('should pipe enc output to dec', () => {
         const enc = execCliBin(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);
         const result = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass'], enc.stdout);
         expect(result.status).toBe(0);
         expect(result.stdout.trim()).toBe(clearText);
      });

      it('should fail rather than report success on empty piped input', () => {
         const enc = execCliBin(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);
         const good = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass'], enc.stdout);
         expect(good.status).toBe(0);

         // Exiting 0 here reads as a successful decrypt of nothing
         const result = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass'], '');
         expect(result.status).toBe(1);
         expect(result.stdout).toBe('');
      });
   });

   describe('untrusted hint rendering', () => {
      const ESC = '\u001b';
      const BEL = '\u0007';
      const hintPath = path.resolve(tmpDir, 'test-hint.bin');
      // Written by whoever encrypted the data, so it reaches the reader's terminal
      const escapingHint = `${ESC}]0;PWNED${BEL}${ESC}[2K\rFAKE`;

      afterEach(() => {
         if (fs.existsSync(hintPath)) {
            fs.unlinkSync(hintPath);
         }
      });

      it('shows control characters in a hint instead of running them', () => {
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--outfile',
               hintPath,
               '--pwds',
               'pass',
               '--hints',
               escapingHint,
            ],
            clearText,
         );
         expect(enc.status).toBe(0);

         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', hintPath]);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('FAKE');
         expect(result.stdout).toContain('\\u001b');
         expect(result.stdout).not.toContain(ESC);
         expect(result.stdout).not.toContain(BEL);
      });
   });

   describe('no controlling terminal', () => {
      // setsid is the only portable way to drop the controlling terminal, and it is linux only
      const hasSetsid = process.platform === 'linux' && spawnSync('which', ['setsid']).status === 0;

      it.skipIf(!hasSetsid)('reports missing options rather than prompting for them', () => {
         const result = spawnSync(
            'setsid',
            ['node', cliPath, 'enc', 'some text', '--iters', '1000000', '--pwds', 'pass'],
            { encoding: 'utf-8', input: '' },
         );

         expect(result.status).toBe(1);
         expect(result.stderr).toContain('required in silent mode');
         // A prompt here would echo the answer into the data stream
         expect(result.stdout).toBe('');
      });
   });

   describe('info command', () => {
      it('should throw error for invalid cred length on info', () => {
         const result = execCli(['info', '--cred', 'SHORT', '--silent', '--infile', encryptedFilePath]);
         expect(result.status).toBe(1);
      });

      it('should throw error for missing infile', () => {
         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', 'DOES_NOT_EXIST.qq']);
         expect(result.status).toBe(1);
      });

      it('should print properties of ciphered input', () => {
         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', encryptedFilePath]);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('Cipher and Mode');
         expect(result.stdout).toContain('Loops');
      });

      it('should show correct values for known encryption params', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-info-params.bin');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--algs',
               'AES-GCM',
               '--outfile',
               tmpEnc,
               '--pwds',
               'p1',
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const result = execCli(['info', '--cred', userCred, '--silent', '--infile', tmpEnc]);
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('AES 256 GCM');
         expect(result.stdout).toContain('1000000');
         expect(result.stdout).toContain('Loops             : 1');
         fs.unlinkSync(tmpEnc);
      });

      it('should save info output to file with --outfile', () => {
         const result = execCli([
            'info',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--outfile',
            infoFilePath,
         ]);
         expect(result.status).toBe(0);
         const output = fs.readFileSync(infoFilePath, 'utf-8');
         expect(output).toContain('Cipher and Mode');
         expect(output).toContain('Loops');
      });

      it('should reject --b64url out on info command', () => {
         const result = execCli([
            'info',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--b64url',
            'out',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('not supported with the info command');
      });

      it('should reject --b64url both on info command', () => {
         const result = execCli([
            'info',
            '--cred',
            userCred,
            '--silent',
            '--infile',
            encryptedFilePath,
            '--b64url',
            'both',
         ]);
         expect(result.status).toBe(1);
         expect(result.stderr).toContain('not supported with the info command');
      });

      it('should accept --b64url in on info command', () => {
         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--b64url', 'out'],
            clearText,
         );
         expect(enc.status).toBe(0);
         const result = execCli(['info', '--cred', userCred, '--silent', '--b64url', 'in'], enc.stdout.trim());
         expect(result.status).toBe(0);
         expect(result.stdout).toContain('Cipher and Mode');
      });
   });

   describe('--b64url flag', () => {
      const b64urlRe = /^[A-Za-z0-9_-]+$/;

      it('should reject invalid choice', () => {
         const result = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--b64url', 'bogus'],
            clearText,
         );
         expect(result.status).toBe(1);
         expect(result.stderr).toMatch(/b64url/i);
      });

      it('should emit b64url cipher to stdout when --b64url out', () => {
         const result = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--b64url', 'out'],
            clearText,
         );
         expect(result.status).toBe(0);
         const out = result.stdout.trim();
         expect(out).toMatch(b64urlRe);
         // not JSON armor and not raw binary chars
         expect(out.startsWith('{')).toBe(false);
      });

      it('should write b64url cipher to --outfile when --b64url out', () => {
         const tmpEnc = path.resolve(tmpDir, 'test-b64url-out.txt');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--pwds',
               'pass',
               '--b64url',
               'out',
               '--outfile',
               tmpEnc,
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         const written = fs.readFileSync(tmpEnc, 'utf-8').trim();
         expect(written).toMatch(b64urlRe);
         fs.unlinkSync(tmpEnc);
      });

      it('should accept b64url cipher input on dec when --b64url in', () => {
         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--b64url', 'out'],
            clearText,
         );
         expect(enc.status).toBe(0);
         const cipherB64 = enc.stdout.trim();
         const dec = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass', '--b64url', 'in'], cipherB64);
         expect(dec.status).toBe(0);
         expect(dec.stdout.trim()).toBe(clearText);
      });

      it('should roundtrip clear text through --b64url both', () => {
         const clearB64 = Buffer.from(clearText, 'utf-8').toString('base64url');
         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--b64url', 'both'],
            clearB64,
         );
         expect(enc.status).toBe(0);
         const cipherB64 = enc.stdout.trim();
         expect(cipherB64).toMatch(b64urlRe);
         const dec = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass', '--b64url', 'both'], cipherB64);
         expect(dec.status).toBe(0);
         // dec output is b64url-encoded clear bytes
         expect(dec.stdout.trim()).toBe(clearB64);
         expect(Buffer.from(dec.stdout.trim(), 'base64url').toString('utf-8')).toBe(clearText);
      });

      it('should roundtrip via files with --b64url', () => {
         const rtEnc = path.resolve(tmpDir, 'test-b64url-rt.txt');
         const rtDec = path.resolve(tmpDir, 'test-b64url-rt-dec.txt');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--iters',
               '1000000',
               '--pwds',
               'pass',
               '--b64url',
               'out',
               '--outfile',
               rtEnc,
            ],
            clearText,
         );
         expect(enc.status).toBe(0);
         expect(fs.readFileSync(rtEnc, 'utf-8').trim()).toMatch(b64urlRe);
         const dec = execCli([
            'dec',
            '--cred',
            userCred,
            '--silent',
            '--pwds',
            'pass',
            '--b64url',
            'in',
            '--infile',
            rtEnc,
            '--outfile',
            rtDec,
         ]);
         expect(dec.status).toBe(0);
         expect(fs.readFileSync(rtDec, 'utf-8').trim()).toBe(clearText);
         fs.unlinkSync(rtEnc);
         fs.unlinkSync(rtDec);
      });

      it('should fall back to probe on dec when --b64url in is not specified', () => {
         // existing JSON-armor path still works without --b64url
         const enc = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'],
            clearText,
         );
         expect(enc.status).toBe(0);
         // enc to TTY would emit JSON armor; here piped/non-TTY emits binary, so re-encode as JSON for the probe path
         const binEnc = path.resolve(tmpDir, 'test-b64url-probe.bin');
         const jsonEnc = path.resolve(tmpDir, 'test-b64url-probe.json');
         const enc2 = execCli(
            ['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass', '--outfile', binEnc],
            clearText,
         );
         expect(enc2.status).toBe(0);
         const cipherArmor = JSON.stringify({ ct: fs.readFileSync(binEnc).toString('base64url') });
         fs.writeFileSync(jsonEnc, cipherArmor, 'utf-8');
         const dec = execCli(['dec', '--cred', userCred, '--silent', '--pwds', 'pass', '--infile', jsonEnc]);
         expect(dec.status).toBe(0);
         expect(dec.stdout.trim()).toBe(clearText);
         fs.unlinkSync(binEnc);
         fs.unlinkSync(jsonEnc);
      });
   });

   describe('--debug argument masking', () => {
      const secretText = 'SENTINEL-CLEAR-TEXT';
      const secretPwd = 'SENTINEL-PASSWORD';
      const secretHint = 'SENTINEL-HINT';

      it('keeps credential, passwords, hints, and text out of the argument dump', () => {
         const tmpEnc = path.resolve(tmpDir, 'debug-mask.bin');
         const enc = execCli([
            'enc',
            secretText,
            '--cred',
            userCred,
            '--silent',
            '--debug',
            '--iters',
            '1000000',
            '--outfile',
            tmpEnc,
            '--pwds',
            secretPwd,
            '--hints',
            secretHint,
         ]);

         expect(enc.status).toBe(0);
         expect(enc.stderr).toContain('args ->');
         for (const secret of [secretText, secretPwd, secretHint, userCred]) {
            expect(enc.stderr).not.toContain(secret);
         }
         fs.unlinkSync(tmpEnc);
      });

      it('masks arguments after a double dash', () => {
         const result = execCli(['enc', '--cred', userCred, '--silent', '--debug', '--', secretText], '');

         expect(result.stderr).toContain('args ->');
         expect(result.stderr).not.toContain(secretText);
      });

      it('reports the length of the masked text', () => {
         const info = execCli(['info', secretText, '--silent', '--debug']);

         expect(info.stderr).toContain(`****** (${secretText.length} chars)`);
         expect(info.stderr).not.toContain(secretText);
      });

      it('still shows values that carry no secret', () => {
         const tmpEnc = path.resolve(tmpDir, 'debug-show.bin');
         const enc = execCli(
            [
               'enc',
               '--cred',
               userCred,
               '--silent',
               '--debug',
               '--iters',
               '1000000',
               '--algs',
               'AES-GCM',
               '--outfile',
               tmpEnc,
               '--pwds',
               secretPwd,
            ],
            clearText,
         );

         expect(enc.status).toBe(0);
         expect(enc.stderr).toContain('AES-GCM');
         expect(enc.stderr).toContain('1000000');
         expect(enc.stderr).toContain(tmpEnc);
         fs.unlinkSync(tmpEnc);
      });
   });
});
