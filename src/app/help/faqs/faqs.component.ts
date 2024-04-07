import { Component, ViewEncapsulation } from '@angular/core';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { animate, state, style, transition, trigger } from '@angular/animations';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';


export interface FAQElement {
   position: number;
   question: string;
   answer: string;
}

@Component({
   selector: 'app-faqs',
   standalone: true,
   templateUrl: './faqs.component.html',
   styleUrl: './faqs.component.scss',
   animations: [
      trigger('detailExpand', [
         state('collapsed,void', style({ height: '0px', minHeight: '0' })),
         state('expanded', style({ height: '*' })),
         transition('expanded <=> collapsed', animate('225ms cubic-bezier(0.4, 0.0, 0.2, 1)')),
      ]),
   ],
   encapsulation: ViewEncapsulation.None,
   imports: [
      MatTableModule, MatInputModule, MatFormFieldModule, MatIconModule,
      MatButtonModule,
   ],
})
export class FaqsComponent {

   public allExpanded = false;
   public expandedPositions = new Array();
   public displayedColumns: string[] = ['position', 'question'];
   public dataSource: MatTableDataSource<FAQElement>;

   constructor() {
      for (let [index, element] of ELEMENT_DATA.entries()) {
         element['position'] = index + 1;
      }
      this.dataSource = new MatTableDataSource(ELEMENT_DATA);
   }

   applyFilter(event: Event) {
      const filterValue = (event.target as HTMLInputElement).value || '';
      this.dataSource.filter = filterValue.trim().toLowerCase();
   }

   addOrRemove(position: number) {
      if (this.expandedPositions.includes(position)) {
         this.expandedPositions = this.expandedPositions.filter(e => e !== position);
      } else {
         this.expandedPositions.push(position);
      }
   }

   onToggleExpand() {
      if (this.allExpanded) {
         this.expandedPositions = new Array();
      } else {
         this.expandedPositions = [...Array(ELEMENT_DATA.length).keys()];
      }
      this.allExpanded = !this.allExpanded;
   }

}

const ELEMENT_DATA: FAQElement[] = [
   {
      position: 0,
      question: 'Who can decrypt the data I encypt with Quick Crypt?',
      answer: `Quick Crypt was designed to help your encrypt and decrypt
      your own information rather than to exchange data with
      others. Quick Crypt generates a cryptographic key every time you
      encrypt or decrypt data. That key is derived from two inputs:
      <ol type='i'>
         <li>The password you provide for each cryptographic process</li>
         <li>A user credential that is only accessible with your Passkey</li>
      </ol>
      <p>To decrypt a message, someone needs both the password
      you used during encyption and a Passkey restricting access
      to you Quick Crypt user credential.</p>
      <p>Unless you share your password and Passkey with someone,
      only you should be able to decrypt that data that you encrypt.</p>`
   },

   {
      position: 0,
      question: 'What are Passkeys and why does Quick Crypt use them?',
      answer: `There are many good descriptions online.
      <a href="https://support.apple.com/en-us/102195" target="_blank">
      Apple describes them</a> as:
      <blockquote cite="https://support.apple.com/en-us/102195">
      Passkeys are built on the WebAuthentication (or "WebAuthn") standard, which uses public-key cryptography.
      During account registration, the operating system creates a unique cryptographic key pair to associate
      with an account for the app or website. These keys are generated by the device, securely and uniquely,
      for every account.
      </blockquote>
      <p>Although Passkey can operate without passwords, Quick Crypt uses passwords
      and Passkeys. Quick Crypt uses Passkeys for two reasons. <i>First</i>, it is a good security practice
      to protect secrets with both something you know, which in Quick Crypt is
      encryption passwords you enter, and with something you have, which is the Passkey.
      </p>
      <p><i>Second</i>, Quick Crypt relies on Passkeys being strongly associated
      with specific websites. A potential risk of online encryption tools is that
      a rogue website could impersonate another site, trick people into decrypting
      data on the rogue
      site, and then steal the results. Quick Crypt removes that risk by requiring
      a Passkey that is bound to Quick Crypt's domain name. The Passkey makes it infeasible
      for even a website that took Quick Crypt's source code to decrypt your data.
      </p>`
   },

   {
      position: 0,
      question: 'Does Quick Crypt store or process Personal Identifiable Information (PII)?',
      answer: `Quick Crypt does not collect, request, or process PII. When you enter a user name or a
      passkey description, you may use whatever values you choose. It is best not to use PII
      for those values, but even if you used something like an email address
      as a user name, Quick Crypt treats that as an opaque value and will not contact
      you. If you change your user name or passkey descriptions, previous values are
      not retained.`
   },

   {
      position: 0,
      question: 'What information does Quick Crypt store and where is it stored?',
      answer: `<table class="tg">
      <thead>
        <tr>
          <th class="tg-fymr">What Information</th>
          <th class="tg-fymr">Stored Where</th>
          <th class="tg-fymr">Removal</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="tg-0pky">Unencrypted or encrypted data</td>
          <td class="tg-0pky">Not stored</td>
          <td class="tg-0pky">Only present in browser edit fields.
            Close your browser tab, navigate away, or empty the browser edit fields to remove</td>
        </tr>
        <tr>
          <td class="tg-0pky">Passwords and hints used for encryption and decryption</td>
          <td class="tg-0pky">Never stored, optionally cached</td>
          <td class="tg-0pky">When password caching is enabled within "Advanced Encryption Options," the last
            entered password is cached in browser memory. Click the "Forget Pwd" button to remove.</td>
        </tr>
        <tr>
          <td class="tg-0pky">Encryption and decryption preferences such as the symmetric cipher </td>
          <td class="tg-0pky">Browser local storage on your system</td>
          <td class="tg-0pky">Within the "Advanced Encryption Options" section on the encryption page, click the
            "Reset to Defaults" button<br> </td>
        </tr>
        <tr>
          <td class="tg-0pky">Last user name and user ID signed into Quick Crypt</td>
          <td class="tg-0pky">Browser local storage on your system</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, click the "Sign Out" button, then click the
            "Sign in as a different user" button</td>
        </tr>
        <tr>
          <td class="tg-0pky">Currently signed-in user name and credential</td>
          <td class="tg-0pky">Browser sessions storage on your system</td>
          <td class="tg-0pky">Close the Quick Crypt tab in your browser or navigate to another website</td>
        </tr>
        <tr>
          <td class="tg-0pky">Public-key portions of each passkey</td>
          <td class="tg-0pky">Server side storage in AWS DynamoDB</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, click the trash can icon for the passkey
            you want to remove</td>
        </tr>
        <tr>
          <td class="tg-0pky">User name, ID, and credential associated with public-key portions of passkeys</td>
          <td class="tg-0pky">Server side storage in AWS DynamoDB</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, delete all passkeys. This will cause the removal
            of all server-side data (passkeys and user name)</td>
        </tr>
      </tbody>
    </table>`
   },

   {
      position: 0,
      question: 'Does Quick Crypt store or upload the passwords I used to encrypt data?',
      answer: `No. See the previous question about the information Quick Crypt stores for
      more detail.`
   },

   {
      position: 0,
      question: 'Does Quick Crypt store or upload the unencrypted or encrypted data I enter?',
      answer: `No. See the previous question about the information Quick Crypt stores for
      more detail.`
   },

   {
      position: 0,
      question: 'Can I used Quick Crypt on text or binary files?',
      answer: `You can upload a text file with the <i>Clear File</i> button
      or save cipher text as a file with the <i>Cipher File</i>
      button on the main page. Quick Crypt does not yet support binary
      files, but this may be added in the future.`
   },

   {
      position: 0,
      question: 'Can I used Quick Crypt to send secrets to other people?',
      answer: `<p>You can, but you should probalby find a better way.
      You can, but you should find a better way. Quick Crypt was designed
      to encrypt and decrypt your own data rather than to share data securely
      with others. Decryption with Quick Crypt can done by someone with both
      the encryption password and a passkey granting access to your user
      credential. Passwords are easy to share (although doing so security is
      not always easy), and passkeys can be shared with a good management
      tool like Bitwarden or 1Password. If the intended recipient has both,
      you can send them encrypted data that they can decrypt with Quick Crypt.
      But again, there are better ways to do this.`
   },

   {
      position: 0,
      question: 'Can I create more than one passkey or user account?',
      answer: `Yes, to both. Once signed in, you can create additional passkeys
      from the slide-out panel opened with the 3-line button in the toolbar.
      You can also sign out from the slide-out panel and create a new user
      identity with a new passkey. Please add only as many passkeys and users
      as needed to reduce the load on Quick Crypt servers. Identities that
      look like abuse may be purged.`
   },

   {
      position: 0,
      question: 'How do I delete passkeys?',
      answer: `Once signed in, you can delete passkeys from the slide-out panel
      opened with the 3-line button in the toolbar. This will remove the
      public-key portion of the paskey from Quick Crypt servers. You must then
      use your local passkey management tool to delete the passkey from your
      system.`
   },

   {
      position: 0,
      question: 'How do I delete my Quick Crypt user identity entirely?',
      answer: `Once signed in, delete all passkeys from the slide-out panel opened
      with the 3-line button in the toolbar. Deleting the last passkey reference
      will entirely delete your Quick Crypt user identity from Quick Crypt servers.
      Once removed, you cannot use Quick Crypt to decrypt previously encrypted data
      with the removed user identity. This is not reversible, even with the recovery
      link. You could, however, use data in the recovery link with other tools to
      decrypt your data (see the related question). Remember to also delete passkeys
      from your system using your local passkey management tool.`
   },

   {
      position: 0,
      question: 'Can I decrypt my data if Quick Crypt goes away?',
      answer: `Yes, as long as you save your recovery link. The user credential in
      your recovery link and the password used during encryption are the only inputs
      needed to decrypt data previously encrypted with Quick Crypt. If you want to
      be sure someone else can recreate Quick Crypt's logic,
      <a href="https://github.com/bschick/qcrypt" target="_blank">
      download the code</a> or the
      <a href="/help/protocol">protocol description</a>. Other tools could be used
      in a multi-step process. The Quick Crypt source repo also contains a
      <a href="https://github.com/bschick/qcrypt/blob/main/qcrypt.ts" target="_blank">
      simple command-line tool</a> that can decrypt
      Quick Crypt cipher text by running:<blockquote>
      > npx tsx ./qcrypt.ts</blockquote>`
   },

   {
      position: 0,
      question: 'I have read that web-apps cannot be trusted for encryption.',
      answer: `That's not a question! Much has changed over the past decade,
      making web browsers and security protocols more robust and
      trustworthy. Web standards and tools are imperfect, but so are installed
      binary applications. A longer write-up is warranted someday.`
   },

   {
      position: 0,
      question: 'Can Quick Crypt decrypt cipher text created by other tools?',
      answer: `No, Quick Crypt was not designed to interoperate with cipher text
      from other tools. Quick Crypt's goal are described on the
      <a href="/help/overview">overview page</a>`
   },

   {
      position: 0,
      question: 'Can other tools decrypt cipher text created by Quick Crypt?',
      answer: `Yes, as long as you save your recovery link, remember your
      encryption password, and follow
      <a href="/help/protocol">Quick Crypt's protocol</a>, you can use other
      tools to decrypt cipher text created by Quick Crypt in a multi-step process.
      The steps aren't documented yet.`
   },

   {
      position: 0,
      question: 'Is the \'link\' Cipher Armor format secure?',
      answer: `<p>Using other cipher armor formats and navigating directly to
      Quick Crypt's website is safer than using the 'link' format.</p>
      <p>The risk with following cipher armor links is that the embedded URL
      cannot be encrypted (or validated) to be usable in a browser.
      If an attacker can manipulate your
      stored cipher text, they could edit the embedded URL, sending you to an
      untrusted site.
      Because the untrusted site cannot access your Quick Crypt passkey,
      it cannot obtain your user
      credential or decrypt your data (see the 'threat modeling question').
      However, an untrusted site could prompt you for your encryption password
      to obtain some of the information needed for decryption. It could also
      try to trick you into encrypting new data.</p>
      <p>The link format is only recommended when you are concerned about
      privacy and not the potential manipulation of stored cipher text. In that
      situation, having a link directly to the Quick Crypt site is very convienent.
      </p>`
   },

   {
      position: 0,
      question: 'How is data encrypted and decrypted, and which crypto implementations are used?',
      answer: `<p>See the detailed description on the
      <a href="/help/protocol">protocol help page</a>.</p><p>
      Quick Crypt uses well-established cryptographic functions implemented by
      web browsers and libsodium.
      All cryptographic functions are run in your browser, ensuring your data remains local.
      The primary cryptographic functions are listed below. <i>SubtleCrypto</i>
      means the function is implemented in your browser's (Chrome, Safari, Edge, etc)
      <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto" target="_blank">
      SubtleCrypto API</a>. <i>Libsodium</i> means
      the function is implemented by the open-source
      <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a> bundled into
      the Quick Crypt web-app.</p>
      <ol type='i'>
         <li><b>HKDF and PBKDF2 Key Derivation:</b> SubtleCrypto
         <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey" target="_blank">deriveKey()</a>
         </li>
         <li><b>AES 256 GCM Cipher:</b> SubtleCrypto <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt"
         target="_blank">encrypt()</a> and
         <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt" target="_blank">decrypt()</a>
         </li>
         <li><b>XChaCha20 Poly1305 Cipher:</b> libsodium
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction"
         target="_blank">crypto_aead_xchacha20poly1305_ietf_encrypt()</a> and
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction"
         target="_blank">crypto_aead_xchacha20poly1305_ietf_decrypt()</a>
         </li>
         <li><b>AEGIS 256 Cipher:</b> libsodium <a href="https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256"
         target="_blank">crypto_aead_aegis256_encrypt()</a> and
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256"
         target="_blank">crypto_aead_aegis256_decrypt()</a>
         </li>
         <li><b>HMAC Signatures:</b> SubtleCrypto <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign"
         target="_blank">sign()</a> and <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify"
         target="_blank">verify()</a>
         </li>
      </ol>`
   },

   {
      position: 0,
      question: 'Can I decrypt my data if I forget the password I used to encrypt it?',
      answer: `There is no way to decrypt that data. Quick Crypts needs both
      the password you used to encrypt the data and a Passkey to access your user
      credential. Your recovery link lets you create a new passkey, but there is
      no way to recover a lost password. Consider using a password hint next time.`
   },

   {
      position: 0,
      question: 'What should I do if I cannot locate my passkey but have my recovery link?',
      answer: `Paste your recovery link into your browser's address bar. Quick Crypt
      will delete all existing passkeys and creating a new one.`
   },

   {
      position: 0,
      question: 'What happens if I cannot locate my passkey or recovery link?',
      answer: `Losing both your passkeys and recovery link is similar to forgetting
      your encryption password. There is no way to decrypt previously
      encrypted data or encrypt more data, but you can create a new user identity
      and start over.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained a password I used for encryption?',
      answer: `Your data is still protected.
      The potential attacker also needs your encrypted data and your Passkey to decrypt it.
      Without a passkey or recovery link to access your user credential,
      an attacker cannot decrypt your data. Regardless, the best response to a stolen password
      is to re-encrypt your data with a new password and delete any cipher text encrypted with
      the stolen password.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtains my recovery link or passkey?',
      answer: `Your data is still protected.
      The potential attacker also needs your encrypted data and the password
      you used during encryption to decrypt it. Without your encryption password,
      the attacker cannot decrypt your data. Regardless, the best response to a stolen
      recovery link or passkey is to create a
      new Quick Crypt user, re-encrypt your data, and then delete
      the previous cipher text and your previous user identity.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtains my recovery link or passkey and a password I used for encryption?',
      answer: `The potential attacker also needs your encrypted data to decrypt it.
      If the attacker also has your encrypted data, your secret information may be
      exposed. Regardless, the best response to a stolen
      recovery link or passkey and password is to create a
      new Quick Crypt user, re-encrypt your data with a new password, and then delete
      the previous cipher text and your previous user identity.`
   },

   {
      position: 0,
      question: 'Can I use Quick Crypt without entering encryption passwords?',
      answer: `No, but you can get close. Quick Crypt lets you set the minimum
      password strength to a level requiring only one character passwords.
      Since passwords are always combined with a much longer user
      credential accessed with
      your Passkey, this is not as insecure as it may sound. You can also use password
      hints to help you remember your passwords.
      While strong passwords protect your data better, weak passwords or
      overly descriptive hints only reduce encryption security to the strength of
      Passkeys, which are trusted by many top websites. This design aligns with
      Quick Crypt's goal of making it hard to screw up.`
   },

   {
      position: 0,
      question: 'Is my password hint encrypted?',
      answer: `Yes, password hints are encrypted with a key derived from
      your user credential and accessed with your Quick Crypt passkey.
      For the most robust protection of your secret information, avoid
      hints that make it easy for others to guess your encryption password.
      That way, you are protected even if your passkey or recovery link
      is stolen.`
   },

   {
      position: 0,
      question: 'Has thread modeling been done for Quick Crypt?',
      answer: `Only informally, and we'd welcome contributions. These areas have
      been considered:
      <ol type='i'>
         <li><b>Coding errors:</b> We've done our best, but this is always a possible weakness.
         Please <a href="https://github.com/bschick/qcrypt" target="_blank">review the code</a> and
         <a href="https://github.com/bschick/qcrypt/issues" target="_blank">report any issues</a>
         you find. Quick Crypt may open a bug bounty program to
         encourage reporting.</li>
         <li><b>Supply chain attacks:</b> This is a growing security issue for all software.
         Quick Crypt tries to limit the surface area of attack by using a small number
         of well-known open-source libraries (and your web browser of choice). See the
         <a href="/help/overview">overview page</a> for a list of third-party package
         dependencies. Quick Crypt bundles all libraries into a 'single page web app.'
         This means that, much like a native binary application, dependencies are
         integrated at build time and never downloaded on the fly, better ensuring
         their integrity.
         </li>
         <li><b>Various web-app attacks:</b> Quick Crypt uses the latest web-app security
         protocols (csp, cors, modern cert, sri, referrer-policy, hsts, xfo, etc.)
         and aims to maintain an A+ rating at test sites like
         <a href="https://observatory.mozilla.org/" target="_blank">Mozilla Observatory</a>.
         As described above, Quick Crypt also bundles all libraries into a
         'single-page web app' to better ensure their integrity.
         </li>
         <li><b>Server-side data theft or logic injection:</b> Quick Crypt uses AWS
         for server-side logic
         and data storage. The AWS account follows best practices and uses AWS Config
         and AWS Security Hub to help detect problems. Only a few well-known people
         have access to the server accounts, and only one person can access
         server-side data like user credentials and the public-key portion of
         passkeys.
         </li>
         <li><b>Website impersonation:</b> Several well-known security breaches
         occurred when an untrusted site impersonated a trusted website.
         Since Quick Crypt is an open-source project, an attacker could create
         a site that looks identical and has a very similar domain to Quick
         Crypt and try to collect decrypted data. Quick Crypt removes
         decryption risk by requiring a user
         credential stored server-side and only accessible with a Passkey bound to
         Quick Crypt's domain. The user credential and Passkeys make it
         infeasible for any other website, even one that uses Quick Crypt's source code,
         to decrypt your data since browsers are not fooled by similar looking sites
         or domain names and will not use a Passkey bound to Quick Crypt with another
         website. Quick Crypt cannot prevent users from starting with an untrusted
         website and entering clear text or passwords. That is true of any website,
         and the best way to avoid this risk is to navigate directly to
         Quick Crypt or save it as a bookmark.
         </li>
         <li><b>Stolen user passkeys, recovery links, or encryption passwords:</b>
         See the related questions about an untrusted user obtaining your
         passkeys, recovery links, or encryption passwords. Those questions describe
         the best response to each type of data exposure.
         </li>
      </ol>`
   },

   {
      position: 0,
      question: 'How should I decide which cipher mode to use?',
      answer: `Quick Crypt offers only well-established and trusted
      <a href="https://en.wikipedia.org/wiki/Authenticated_encryption" target="_blank">
      authenticated cipher</a> modes that provide privacy and authenticity.
      None are a bad choice, and selecting which mode to use depends
      on your own criteria.
      <ul>
      <li>If you want a mode implemented by your browser vendor, use <b>AES 256 GCM</b>.
      </li>
      <li>If you want a mode <i>not</i> implemented by your browser vendor,
      use <b>XChaCha20 Poly1305</b> or <b>AEGIS 256</b>,
      which are from the open-source
      <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a>.
      </li>
      <li>If you really don't trust your browser vendor, you probably shouldn't
      use Quick Crypt or find a browser you trust.
      </li>
      <li>If you want the most recently created cipher mode, use <b>AEGIS 256</b>.
      </li>
      <li>If you want the most established and studied mode, use <b>AES 256 GCM</b>,
      which is at the core of TLS 1.3 and used more than any other cipher.</li>
      <li>If you want the smallest resulting cipher text (by only 16 characters),
      use <b>AES 256 GCM</b>.
      </li>
      <li>You will not find a universal agreement about the "safest" mode, but the
      <a href="https://doc.libsodium.org/secret-key_cryptography/aead#tl-dr-which-one-should-i-use" target="_blank">
      libsodium project recommends</a> <b>AEGIS 256</b> first, then <b>XChaCha20 Poly1305</b>,
        and <b>AES 256 GCM</b> last.
      </li>`
   },

   {
      position: 0,
      question: 'Why is XChaCha20 offered rather than IETF ChaCha20?',
      answer: `Quick Crypt uses random nonce values for cipher initialization
      vectors, and XChaCha20 is safer than ChaCha20 with random nonce values.
      Since Quick Crypt
      never intentionally reuses cipher keys, ChaCha20 would
      be suitable. IETF ChaCha20's one advantage is standardization, but
      since interoperability with other tools was not a Quick Crypt goal,
      XChaCha20 was selected as a better overall cipher mode.`
   },

   {
      position: 0,
      question: 'Why does Quick Crypt use both HMACs and AEAD ciphers?',
      answer: `This is for defense-in-depth and to allow Quick Crypt to
      safely use and display metadata like password hints before the
      primary decryption algorithm. Imagine an attacker could modify your
      encrypted data and knows of a bug in Chrome's AES GCM cipher. Although
      unlikely, that could allow an attacker to craft the cipher text such
      that "something bad" happened when you decrypted it. The HMAC
      signature test upfront means there would need to be problems with
      both the HMAC and the cipher algorithms, which is even more unlikely.`
   },
];