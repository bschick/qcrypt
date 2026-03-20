import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawnSync, SpawnSyncReturns } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

describe('CLI App', () => {
    const cliPath = path.resolve(__dirname, '../../../dist/cli/qcrypt.cjs');
    const tmpDir = path.resolve(__dirname, '../tmp');
    const userCred = '_sHEi_YNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
    const wrongCred = 'AAAAAYNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
    const clearText = 'This is a secret message to test the CLI.';

    const inFilePath = path.resolve(tmpDir, 'test-in.txt');
    const encryptedFilePath = path.resolve(tmpDir, 'test-enc.bin');
    const decryptedFilePath = path.resolve(tmpDir, 'test-dec.txt');
    const infoFilePath = path.resolve(tmpDir, 'test-info.txt');

    const execCli = (args: string[], input?: string): SpawnSyncReturns<string> => {
        const result = spawnSync('node', [cliPath, ...args], {
            encoding: 'utf-8',
            input: input ?? ''
        });
        if (result.status !== 0) {
            console.error(`Command failed: node ${cliPath} ${args.join(' ')}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
        }
        return result;
    };

    beforeAll(() => {
        if (!process.env['SKIP_BUILD']) {
            console.log('Building CLI before running tests...');
            execSync('pnpm nx build cli', { stdio: 'inherit' });
        }
        fs.mkdirSync(tmpDir, { recursive: true });
        fs.writeFileSync(inFilePath, clearText, 'utf-8');
    });

    afterAll(() => {
        [inFilePath, encryptedFilePath, decryptedFilePath, infoFilePath].forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    fs.unlinkSync(file);
                } catch (err) {
                    console.error(`Failed to clean up file ${file}:`, err);
                }
            }
        });
    });

    describe('enc command', () => {
        it('should throw error when provided invalid cred length', () => {
            const result = execCli(['enc', '--cred', 'SHORT', '--silent', '--iters', '1000000', '--pwds', 'pass'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('Invalid character');
        });

        it('should throw error for non-digit iters', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', 'NOTADIGIT', '--pwds', 'pass'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('iters is not a valid number');
        });

        it('should throw error for non-digit loops', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', 'NOTADIGIT', '--pwds', 'pass'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('loops is not a valid number');
        });

        it('should throw error if more algs than loops', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '1', '--algs', 'AES-GCM', 'X20-PLY', '--pwds', 'pass'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('2 algs provided for 1 loops');
        });

        it('should throw error if more pwds than loops', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '1', '--pwds', 'pass1', 'pass2'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('2 pwds provided for 1 loops');
        });

        it('should reject invalid alg options', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '1', '--algs', 'FAKE-CIPHER', '--pwds', 'pass'], clearText);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('Unsupported cipher mode: FAKE-CIPHER.');
        });

        it('should reject --infile and text together', () => {
            const result = execCli(['enc', clearText, '--cred', userCred, '--silent', '--iters', '1000000', '--infile', inFilePath, '--pwds', 'pass']);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('infile');
        });

        it('should accept lowercase algorithm names', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--algs', 'aes-gcm', '--outfile', encryptedFilePath, '--pwds', 'pass'], clearText);
            expect(result.status).toBe(0);
            expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
        });

        it('should encrypt successfully with piped clear text', () => {
             const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', encryptedFilePath, '--pwds', 'pass'], clearText);
             expect(result.status).toBe(0);
             expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
        });

        it('should handle debug flag properly', () => {
            const result = execCli(['enc', '--cred', userCred, '--debug', '--iters', '1000000', '--algs', 'AES-GCM', '--outfile', encryptedFilePath, '--pwds', 'pass'], clearText);
            expect(result.status).toBe(0);
            expect(result.stderr).toContain('args ->'); // debug output goes to stderr
        });

        it('should encrypt using files', () => {
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--infile', inFilePath, '--outfile', encryptedFilePath, '--pwds', 'pass']);
            expect(result.status).toBe(0);
            expect(fs.statSync(encryptedFilePath).size).toBeGreaterThan(0);
        });

        it('should process extra layers and parameters', () => {
            const tmpEnc = path.resolve(tmpDir, 'test-extra.bin');
            const result = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '2', '--algs', 'AES-GCM', 'X20-PLY', '--outfile', tmpEnc, '--pwds', 'pass1', 'pass2'], clearText);
            expect(result.status).toBe(0);
            expect(fs.statSync(tmpEnc).size).toBeGreaterThan(0);
            fs.unlinkSync(tmpEnc);
        });

        it.each([
            ['AES-GCM'],
            ['X20-PLY'],
            ['AEGIS-256'],
        ])('should roundtrip encrypt/decrypt with %s', (alg) => {
            const rtEnc = path.resolve(tmpDir, `test-rt-${alg}.bin`);
            const rtDec = path.resolve(tmpDir, `test-rt-${alg}.txt`);
            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--algs', alg, '--outfile', rtEnc, '--pwds', 'pass'], clearText);
            expect(enc.status).toBe(0);
            const dec = execCli(['dec', '--cred', userCred, '--silent', '--infile', rtEnc, '--outfile', rtDec, '--pwds', 'pass']);
            expect(dec.status).toBe(0);
            expect(fs.readFileSync(rtDec, 'utf-8')).toBe(clearText);
            fs.unlinkSync(rtEnc);
            fs.unlinkSync(rtDec);
        });
    });

    describe('dec command', () => {
        it('should throw error for invalid cred length on decrypt', () => {
             const result = execCli(['dec', '--cred', 'SHORT', '--silent', '--infile', encryptedFilePath, '--pwds', 'pass']);
             expect(result.status).toBe(1);
        });

        it('should throw error when given wrong password', () => {
             const result = execCli(['dec', '--cred', userCred, '--silent', '--infile', encryptedFilePath, '--pwds', 'WRONGPASS']);
             expect(result.status).toBe(1);
             expect(result.stderr).toContain('decryption failed');
        });

        it('should decrypt successfully from file', () => {
             const result = execCli(['dec', '--cred', userCred, '--silent', '--infile', encryptedFilePath, '--outfile', decryptedFilePath, '--pwds', 'pass']);
             expect(result.status).toBe(0);
             expect(fs.readFileSync(decryptedFilePath, 'utf-8')).toBe(clearText);
        });

        it('should decrypt correctly with multiple passwords matching length', () => {
            const rtEnc = path.resolve(tmpDir, 'test-multi.bin');
            const rtDec = path.resolve(tmpDir, 'test-multi.txt');
            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--loops', '2', '--outfile', rtEnc, '--pwds', 'A', 'B'], clearText);
            expect(enc.status).toBe(0);
            const dec = execCli(['dec', '--cred', userCred, '--silent', '--infile', rtEnc, '--outfile', rtDec, '--pwds', 'B', 'A']);
            expect(dec.status).toBe(0);
            expect(fs.readFileSync(rtDec, 'utf-8')).toBe(clearText);
            fs.unlinkSync(rtEnc);
            fs.unlinkSync(rtDec);
        });

        it('should decrypt using default command without dec keyword', () => {
            const result = execCli(['--cred', userCred, '--silent', '--infile', encryptedFilePath, '--outfile', decryptedFilePath, '--pwds', 'pass']);
            expect(result.status).toBe(0);
            expect(fs.readFileSync(decryptedFilePath, 'utf-8')).toBe(clearText);
        });

        it('should fail with wrong credential of valid length', () => {
            const result = execCli(['dec', '--cred', wrongCred, '--silent', '--infile', encryptedFilePath, '--pwds', 'pass']);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('decryption failed');
        });
    });

    describe('input formats', () => {
        it('should roundtrip with JSON cipher armor infile', () => {
            const binEnc = path.resolve(tmpDir, 'test-fmt-bin.bin');
            const jsonEnc = path.resolve(tmpDir, 'test-fmt.json');
            const dec = path.resolve(tmpDir, 'test-fmt-dec.txt');

            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'], clearText);
            expect(enc.status).toBe(0);

            const binData = fs.readFileSync(binEnc);
            const cipherArmor = JSON.stringify({ ct: Buffer.from(binData).toString('base64url') });
            fs.writeFileSync(jsonEnc, cipherArmor, 'utf-8');

            const result = execCli(['dec', '--cred', userCred, '--silent', '--infile', jsonEnc, '--outfile', dec, '--pwds', 'pass']);
            expect(result.status).toBe(0);
            expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

            fs.unlinkSync(binEnc);
            fs.unlinkSync(jsonEnc);
            fs.unlinkSync(dec);
        });

        it('should roundtrip with binary stdin', () => {
            const binEnc = path.resolve(tmpDir, 'test-stdin-bin.bin');
            const dec = path.resolve(tmpDir, 'test-stdin-bin-dec.txt');

            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'], clearText);
            expect(enc.status).toBe(0);

            const binData = fs.readFileSync(binEnc);
            const result = spawnSync('node', [cliPath, 'dec', '--cred', userCred, '--silent', '--outfile', dec, '--pwds', 'pass'], {
                encoding: null,
                input: binData
            });
            expect(result.status).toBe(0);
            expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

            fs.unlinkSync(binEnc);
            fs.unlinkSync(dec);
        });

        it('should roundtrip with JSON cipher armor stdin', () => {
            const binEnc = path.resolve(tmpDir, 'test-stdin-json.bin');
            const dec = path.resolve(tmpDir, 'test-stdin-json-dec.txt');

            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'], clearText);
            expect(enc.status).toBe(0);

            const binData = fs.readFileSync(binEnc);
            const cipherArmor = JSON.stringify({ ct: Buffer.from(binData).toString('base64url') });
            const result = execCli(['dec', '--cred', userCred, '--silent', '--outfile', dec, '--pwds', 'pass'], cipherArmor);
            expect(result.status).toBe(0);
            expect(fs.readFileSync(dec, 'utf-8')).toBe(clearText);

            fs.unlinkSync(binEnc);
            fs.unlinkSync(dec);
        });

        it('should detect binary infile for info command', () => {
            const binEnc = path.resolve(tmpDir, 'test-info-bin.bin');
            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'], clearText);
            expect(enc.status).toBe(0);

            const result = execCli(['info', '--cred', userCred, '--silent', '--infile', binEnc]);
            expect(result.status).toBe(0);
            expect(result.stdout).toContain('Cipher and Mode');

            fs.unlinkSync(binEnc);
        });

        it('should detect JSON infile for info command', () => {
            const binEnc = path.resolve(tmpDir, 'test-info-json.bin');
            const jsonEnc = path.resolve(tmpDir, 'test-info.json');

            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--outfile', binEnc, '--pwds', 'pass'], clearText);
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
            const enc = spawnSync('node', [cliPath, 'enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'], {
                input: clearText,
                encoding: null
            });
            const result = spawnSync('node', [cliPath, 'info', '--cred', userCred, '--silent'], {
                input: enc.stdout,
                encoding: 'utf-8'
            });
            expect(result.status).toBe(0);
            expect(result.stdout).toContain('Cipher and Mode');
            expect(result.stdout).toContain('Loops');
        });

        it('should pipe enc output to dec', () => {
            const enc = spawnSync('node', [cliPath, 'enc', '--cred', userCred, '--silent', '--iters', '1000000', '--pwds', 'pass'], {
                input: clearText,
                encoding: null
            });
            const result = spawnSync('node', [cliPath, 'dec', '--cred', userCred, '--silent', '--pwds', 'pass'], {
                input: enc.stdout,
                encoding: 'utf-8'
            });
            expect(result.status).toBe(0);
            expect(result.stdout.trim()).toBe(clearText);
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
            const enc = execCli(['enc', '--cred', userCred, '--silent', '--iters', '1000000', '--algs', 'AES-GCM', '--outfile', tmpEnc, '--pwds', 'p1'], clearText);
            expect(enc.status).toBe(0);
            const result = execCli(['info', '--cred', userCred, '--silent', '--infile', tmpEnc]);
            expect(result.status).toBe(0);
            expect(result.stdout).toContain('AES 256 GCM');
            expect(result.stdout).toContain('1000000');
            expect(result.stdout).toContain('Loops             : 1');
            fs.unlinkSync(tmpEnc);
        });

        it('should save info output to file with --outfile', () => {
            const result = execCli(['info', '--cred', userCred, '--silent', '--infile', encryptedFilePath, '--outfile', infoFilePath]);
            expect(result.status).toBe(0);
            const output = fs.readFileSync(infoFilePath, 'utf-8');
            expect(output).toContain('Cipher and Mode');
            expect(output).toContain('Loops');
        });
    });
});
