import { Injectable } from '@angular/core';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { base64ToBytes } from './cipher.service';


@Injectable({
   providedIn: 'root'
})
export class AuthenticatorService {

   public siteKey?: Uint8Array;

   constructor() { }

   isAuthenticated(): boolean {
      return this.siteKey ? true : false;
   }

   isUserKnown(): boolean {
      const userId = localStorage.getItem('userid');
      const userName = localStorage.getItem('username');
      return Boolean(userId && userName);
   }

   getUserInfo(): [string | null, string | null] {
      const userId = localStorage.getItem('userid');
      const userName = localStorage.getItem('username');
      return [userId, userName];
   }

   storeUserInfo(userId: string, userName: string) {
      if(!userId || !userName) {
         throw new Error('missing userId or userName');
      }
      localStorage.setItem('userid', userId);
      localStorage.setItem('username', userName);
   }

   removeUserInfo() {
      localStorage.removeItem('userid');
      localStorage.removeItem('username');
   }


   async passkeyLogin(userId: string | null = null): Promise<Uint8Array> {

      if (!userId) {
         userId = localStorage.getItem('userid');
      }

      let optUrl;
      if (!userId) {
         // Trying to link to an existing passkey but have lost track of user id.
         // Start the process without userId just doesn't limit authenticator creds
         // so the user can look for an existing credential
         optUrl = new URL('https://qcrypt.schicks.net/authoptions');
      } else {
         optUrl = new URL(`https://qcrypt.schicks.net/authoptions?userid=${userId}`);
      }

      const optionsResp = await fetch(optUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store'
      });

      console.log('optionsResp, ', optionsResp);
      if (!optionsResp.ok) {
         throw new Error('authentication failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json();
      console.log('optionsJson, ', optionsJson);

      let startAuth;
      try {
         startAuth = await startAuthentication(optionsJson);
      } catch (err) {
         console.error(err);
         throw err;
      }

      // Need to return challenge because in some cases it cannot be bound
      // to a user when created. The server validates it created the challenge
      // and its age
      const expanded = {
         ...startAuth,
         challenge: optionsJson.challenge,
      }

      console.log('expanded ', JSON.stringify(expanded));

      const verifyUrl = new URL('https://qcrypt.schicks.net/verifyauth');
      const verificationResp = await fetch(verifyUrl, {
         method: 'POST',
         mode: 'cors',
         cache: 'no-store',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify(expanded),
      });

      console.log('verifyResp, ', verificationResp);
      if (!verificationResp.ok) {
         throw new Error('authentication failed: ' + await verificationResp.text());
      }

      const verificationJson = await verificationResp.json();
      console.log('verifyJson, ', verificationJson);

      if (!verificationJson || !verificationJson.verified) {
         throw new Error('authentication failed');
      }

      this.storeUserInfo(verificationJson.userId, verificationJson.userName);
      return this.siteKey = base64ToBytes(verificationJson.siteKey);
   }

   async newPasskey(userId?: string, userName?: string): Promise<Uint8Array> {

      let optUrl;
      if (userId) {
         optUrl = new URL(`https://qcrypt.schicks.net/regoptions?userid=${userId}`);
      } else if (userName) {
         optUrl = new URL(`https://qcrypt.schicks.net/regoptions?username=${userName}`);
      } else {
         throw new Error('must provide userId or userName');
      }

      const optionsResp = await fetch(optUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store'
      });

      console.log('optionsResp, ', optionsResp);
      if (!optionsResp.ok) {
         throw new Error('registration failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json();
      console.log('optionsJson ', optionsJson);

      let startReg;
      try {
         startReg = await startRegistration(optionsJson);
      } catch (err) {
         console.error(err);
         throw err;
      }

      // Need to return challenge because in some cases it cannot be bound
      // to a user when created. The server validates it created the challenge
      // and its age (seems odd the userHandle isn't returned from .create)
      const expanded = {
         ...startReg,
         userId: optionsJson.user.id,
         challenge: optionsJson.challenge,
      }

      console.log('expanded ', JSON.stringify(expanded));

      const verifyUrl = new URL('https://qcrypt.schicks.net/verifyreg');
      const verificationResp = await fetch(verifyUrl, {
         method: 'POST',
         mode: 'cors',
         cache: 'no-store',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify(expanded),
      });

      console.log('verifyResp, ', verificationResp);
      if (!verificationResp.ok) {
         throw new Error('registration failed: ' + await verificationResp.text());
      }

      const verificationJson = await verificationResp.json();
      console.log('verifyJson, ', verificationJson);

      if (!verificationJson || !verificationJson.verified) {
         throw new Error('registration failed');
      }

      this.storeUserInfo(optionsJson.user.id, optionsJson.user.name);
      return this.siteKey = base64ToBytes(verificationJson.siteKey);
   }

}

/* OLD

  async createPKSignature(): Promise<Credential | null> {
    console.log('enter createPKSignature')

    const publicKey: PublicKeyCredentialCreationOptions = {
      authenticatorSelection: {
        residentKey: "required"
      },
      challenge: this.challenge,
      rp: {
        id: "t1.schicks.net",
        name: "Quick Crypt"
      }, // For testing, do not include Id directly (comes from browser)
      user: {
        id: this.uid,
        name: "user@qcrypt.schicks.net",
        displayName: "Quick Crypt User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: 3 },
        { type: "public-key", alg: 24 },
        { type: "public-key", alg: 1 },
        { type: "public-key", alg: 7 },
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },]
    };

    return navigator.credentials.create({ publicKey }).then((publicKeyCredential) => {
      if (publicKeyCredential && publicKeyCredential instanceof PublicKeyCredential) {
        const response = publicKeyCredential.response;
        if (response && response instanceof AuthenticatorAttestationResponse) {

          // Access attestationObject ArrayBuffer
          const attestationObj = response.attestationObject;
          console.log(attestationObj);

          // Access client JSON
          const clientJSON = response.clientDataJSON;
          console.log(clientJSON);

          // Return authenticator data ArrayBuffer
          const authenticatorData = response.getAuthenticatorData();
          console.log(authenticatorData);

          // Return public key ArrayBuffer
          const pk = response.getPublicKey();
          console.log(pk);

          // Return public key algorithm identifier
          const pkAlgo = response.getPublicKeyAlgorithm();
          console.log(pkAlgo);

          // Return permissible transports array
          const transports = response.getTransports();
          console.log(transports);

          return null;
        }
      }
      throw new Error("pk creation failed");
    });

  }

  async findPasskeyId(): Promise<string> {

    const publicKey = {
      // not used, but make it look valid incase authenticator is picky
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: "preferred" as UserVerificationRequirement,
    }
    try {
      const credential = await navigator.credentials.get({ publicKey });
      if (credential && credential instanceof PublicKeyCredential) {
        console.log('credentialId: ' + credential.id);
        return credential.id;
      }

      throw new Error("unknown user");
    } catch (err) {
      console.error(err);
      throw new Error("unknown user");
    }
  }


  */