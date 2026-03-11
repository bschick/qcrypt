import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

describe('CLI App', () => {
    const cliPath = path.resolve(__dirname, '../../../dist/cli/qcrypt.cjs');
    const tmpDir = path.resolve(__dirname, '../tmp');
    const userCred = '_sHEi_YNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
    const wrongCred = 'AAAAAYNTLC-YUSxfyIWXtMttNVWkkB9WGfyyZr0ZEc';
    const clearText = 'This is a secret message to test the CLI.';

    const inFilePath = path.resolve(tmpDir, 'test-in.txt');
    const encryptedFilePath = path.resolve(tmpDir, 'test-enc.txt');
    const decryptedFilePath = path.resolve(tmpDir, 'test-dec.txt');
    const infoFilePath = path.resolve(tmpDir, 'test-info.txt');

    const execCli = (command: string, input?: string) => {
        let cmd = `node ${cliPath} ${command}`;
        try {
            return execSync(cmd, { shell: '/bin/sh', encoding: 'utf-8', input: input ?? '' });
        } catch (error: any) {
            console.error(`Command failed: ${cmd}\nstdout: ${error.stdout}\nstderr: ${error.stderr}`);
            return error;
        }
    };

    beforeAll(() => {
        console.log('Building CLI before running tests...');
        execSync('pnpm nx build cli', { stdio: 'inherit' });
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

    let encryptedText: string;

    describe('enc command', () => {
        it('should throw error when provided invalid cred length', () => {
            const result = execCli('enc --cred SHORT --silent --iters 1000000 --pwds pass', clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('Invalid character');
        });

        it('should throw error for non-digit iters', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters NOTADIGIT --pwds pass`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('iters is not a valid number');
        });

        it('should throw error for non-digit loops', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops NOTADIGIT --pwds pass`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('loops is not a valid number');
        });

        it('should throw error if more algs than loops', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops 1 --algs AES-GCM X20-PLY --pwds pass`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('2 algs provided for 1 loops');
        });

        it('should throw error if more pwds than loops', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops 1 --pwds pass1 pass2`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('2 pwds provided for 1 loops');
        });

        it('should reject invalid alg options', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops 1 --algs FAKE-CIPHER --pwds pass`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('Unsupported cipher mode: FAKE-CIPHER.');
        });

        it('should reject --debug and --silent together', () => {
            const result = execCli(`enc --cred ${userCred} --debug --silent --iters 1000000 --pwds pass`, clearText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('debug');
            expect(result.stderr).toContain('silent');
        });

        it('should reject --infile and text together', () => {
            const result = execCli(`enc "${clearText}" --cred ${userCred} --silent --iters 1000000 --infile ${inFilePath} --pwds pass`);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('infile');
        });

        it('should accept lowercase algorithm names', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --algs aes-gcm --pwds pass`, clearText);
            expect(typeof result).toBe('string');
            expect(result).toContain('{"ct":');
        });

        it('should encrypt successfully with piped clear text', () => {
             const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --pwds pass`, clearText);
             expect(typeof result).toBe('string');
             expect(result).toContain('{"ct":');
             encryptedText = (result as string).trim();
        });

        it('should handle debug flag properly', () => {
            const result = execCli(`enc --cred ${userCred} --debug --iters 1000000 --algs AES-GCM --pwds pass`, clearText);
            expect(typeof result).toBe('string');
            expect(result).toContain('args ->'); // should print debug output
        });

        it('should encrypt using files', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --infile ${inFilePath} --outfile ${encryptedFilePath} --pwds pass`);
            expect(typeof result).toBe('string');
            expect(result).toContain('saved to');
            expect(fs.existsSync(encryptedFilePath)).toBeTruthy();
        });

        it('should process extra layers and parameters', () => {
            const result = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops 2 --algs AES-GCM X20-PLY --pwds pass1 pass2`, clearText);
            expect(typeof result).toBe('string');
            expect(result).toContain('{"ct":');
        });

        it.each([
            ['AES-GCM'],
            ['X20-PLY'],
            ['AEGIS-256'],
        ])('should roundtrip encrypt/decrypt with %s', (alg) => {
            const enc = execCli(`enc --cred ${userCred} --silent --iters 1000000 --algs ${alg} --pwds pass`, clearText) as string;
            expect(enc).toContain('{"ct":');
            const dec = execCli(`dec --cred ${userCred} --silent --pwds pass`, enc.trim()) as string;
            expect(dec).toContain(clearText);
        });
    });

    describe('dec command', () => {
        it('should throw error for invalid cred length on decrypt', () => {
             const result = execCli(`dec --cred SHORT --silent --pwds pass`, encryptedText);
             expect(result).toBeInstanceOf(Error);
             expect(result.status).toBe(1);
        });

        it('should throw error when given wrong password', () => {
             const result = execCli(`dec --cred ${userCred} --silent --pwds WRONGPASS`, encryptedText);
             expect(result).toBeInstanceOf(Error);
             expect(result.status).toBe(1);
             expect(result.stderr).toContain('decryption failed');
        });

        it('should decrypt successfully using piped cipher text', () => {
             const result = execCli(`dec --cred ${userCred} --silent --pwds pass`, encryptedText);
             expect(typeof result).toBe('string');
             expect(result).toContain(clearText); 
        });

        it('should decrypt from file to file', () => {
             const result = execCli(`dec --cred ${userCred} --silent --infile ${encryptedFilePath} --outfile ${decryptedFilePath} --pwds pass`);
             expect(typeof result).toBe('string');
             expect(result).toContain('saved to');
             const output = fs.readFileSync(decryptedFilePath, 'utf-8');
             expect(output).toBe(clearText);
        });

        it('should decrypt correctly with multiple passwords matching length', () => {
            const enc = execCli(`enc --cred ${userCred} --silent --iters 1000000 --loops 2 --pwds A B`, clearText) as string;
            const dec = execCli(`dec --cred ${userCred} --silent --pwds B A`, enc.trim()) as string;
            expect(dec).toContain(clearText);
        });

        it('should decrypt using default command without dec keyword', () => {
            const result = execCli(`--cred ${userCred} --silent --pwds pass`, encryptedText);
            expect(typeof result).toBe('string');
            expect(result).toContain(clearText);
        });

        it('should fail with wrong credential of valid length', () => {
            const result = execCli(`dec --cred ${wrongCred} --silent --pwds pass`, encryptedText);
            expect(result).toBeInstanceOf(Error);
            expect(result.status).toBe(1);
            expect(result.stderr).toContain('decryption failed');
        });
    });

    describe('info command', () => {
        it('should throw error for invalid cred length on info', () => {
             const result = execCli(`info --cred SHORT --silent`, encryptedText);
             expect(result).toBeInstanceOf(Error);
             expect(result.status).toBe(1);
        });

        it('should throw error for missing infile', () => {
             const result = execCli(`info --cred ${userCred} --silent --infile DOES_NOT_EXIST.qq`);
             expect(result).toBeInstanceOf(Error);
             expect(result.status).toBe(1);
        });

        it('should print properties of ciphered input', () => {
             const result = execCli(`info --cred ${userCred} --silent`, encryptedText);
             expect(typeof result).toBe('string');
             expect(result).toContain('Cipher and Mode');
             expect(result).toContain('Loops');
        });
        
        it('should verify parameters parsed from a file', () => {
             const result = execCli(`info --cred ${userCred} --silent --infile ${encryptedFilePath}`);
             expect(typeof result).toBe('string');
             expect(result).toContain('Cipher and Mode');
        });

        it('should show correct values for known encryption params', () => {
            const enc = execCli(`enc --cred ${userCred} --silent --iters 1000000 --algs AES-GCM --pwds p1`, clearText) as string;
            const result = execCli(`info --cred ${userCred} --silent`, enc.trim());
            expect(typeof result).toBe('string');
            expect(result).toContain('AES 256 GCM');
            expect(result).toContain('1000000');
            expect(result).toContain('Loops             : 1');
        });

        it('should save info output to file with --outfile', () => {
            const result = execCli(`info --cred ${userCred} --silent --outfile ${infoFilePath}`, encryptedText);
            expect(typeof result).toBe('string');
            expect(result).toContain('saved to');
            const output = fs.readFileSync(infoFilePath, 'utf-8');
            expect(output).toContain('Cipher and Mode');
            expect(output).toContain('Loops');
        });
    });
});
