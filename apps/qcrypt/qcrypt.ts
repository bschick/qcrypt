import * as cs from './src/app/services/cipher.service';
import * as readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { base64ToBytes } from './src/app/services/utils';

function streamFromStr(str: string): ReadableStream<Uint8Array> {
    const data = new TextEncoder().encode(str);
    const blob = new Blob([data], { type: 'application/octet-stream' });
    return blob.stream();
 }

const cipherSvc = new cs.CipherService();
const rl = readline.createInterface({ input, output });

const cipherText = await rl.question('Cipher text (base64): ');
const userCred = await rl.question('Site key (base64): ');
const cipherStream = streamFromStr(cipherText);

const clear = await cipherSvc.decryptStream(
    async (lp, lpEnd, hint) => {
        return [await rl.question(`Password (hint: ${hint}): `), undefined]
    },
    base64ToBytes(userCred),
    cipherStream
);

rl.close();
console.log(clear);
