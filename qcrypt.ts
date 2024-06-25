import * as cs from './src/app/services/cipher.service';
import * as readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const cipherSvc = new cs.CipherService();
const rl = readline.createInterface({ input, output });

const cipherText = await rl.question('Cipher text (base64): ');
const userCred = await rl.question('Site key (base64): ');
const clear = await cipherSvc.decryptString(
    async (hint) => {
        return await rl.question(`Password (hint: ${hint}): `);
    },
    cs.base64ToBytes(userCred),
    cipherText
);

rl.close();
console.log(clear);
