import { AfterViewInit, Component, ViewEncapsulation } from '@angular/core';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { animate, state, style, transition, trigger } from '@angular/animations';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { HttpParams } from '@angular/common/http';
import { FormsModule } from '@angular/forms';


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
      MatButtonModule, FormsModule,
   ],
})
export class FaqsComponent implements AfterViewInit {

   public allExpanded = false;
   public searchTerm = '';
   public expandedPositions = new Array();
   public displayedColumns: string[] = ['position', 'question'];
   public dataSource: MatTableDataSource<FAQElement>;

   constructor() {
      for (let [index, element] of ELEMENT_DATA.entries()) {
         element['position'] = index + 1;
      }
      this.dataSource = new MatTableDataSource(ELEMENT_DATA);
   }

   ngOnInit() {
      const origFilterPredicate = this.dataSource.filterPredicate;
      this.dataSource.filterPredicate =
         (data: FAQElement, filter: string): boolean => {
            const elements = filter.split(',');
            for (let element of elements) {
               if (element && origFilterPredicate(data, element.trim())) {
                  return true;
               }
            }
            return false;
         }
   }

   ngAfterViewInit(): void {
      const params = new HttpParams({ fromString: window.location.search });
      const search = params.get('search');
      if (search) {
         this.searchTerm = search;
         this.applyFilter(search);
         this.onToggleExpand();
      }
   }

   applyFilter(filter: string | null = null) {
      filter = filter ?? '';
      this.dataSource.filter = filter.trim().toLowerCase();
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
         // extra 0 at the front doesn't hurt
         this.expandedPositions = [...Array(ELEMENT_DATA.length).keys(), ELEMENT_DATA.length];
      }
      this.allExpanded = !this.allExpanded;
   }

}

const ELEMENT_DATA: FAQElement[] = [
   {
      position: 0,
      question: 'Who created Quick Crypt and why?',
      answer: `See the <a href="/help/overview">overview page</a>.`
   },

   {
      position: 0,
      question: 'Where should I report problems or get help with Quick Crypt?',
      answer: `Please report problems by <a href="https://github.com/bschick/qcrypt/issues"
      target="_blank">creating an issue on Github</a>. A discussion forum is not yet
      available, but we may create one in the future. You can also try common sites
      like Stack Overflow.`
   },


   {
      position: 0,
      question: 'Who can decrypt the data I encypt with Quick Crypt?',
      answer: `To decrypt data encrypted with Quick Crypt, you need both the
      password you used during encryption and a passkey restricting access to your
      Quick Crypt user credential. Unless you share your passkey and encryption
      password with someone, only you can decrypt data that you have encrypted.`
   },

   {
      position: 0,
      question: 'What are Passkeys and why does Quick Crypt use them?',
      answer: `There are many good descriptions online.
      <a href="https://support.apple.com/en-us/102195" target="_blank">
      Apple describes them</a> as:
      <blockquote cite="https://support.apple.com/en-us/102195">
      Passkeys are built on the WebAuthentication (or "WebAuthn") standard, which uses
      public-key cryptography. During account registration, the operating system creates
      a unique cryptographic key pair to associate with an account for the app or website.
      These keys are generated by the device, securely and uniquely, for every account.
      </blockquote>
      <p>Although passkey can operate without passwords, Quick Crypt uses passwords
      and passkeys. Quick Crypt uses passkeys for two reasons. <i>First</i>, it is a good
      security practice to protect secrets with both something you know, which in Quick
      Crypt is a password you enter during encryption, and with something you have, which
      is the passkey.</p>
      <p><i>Second</i>, Quick Crypt relies on a passkey's binding to the Quick Crypt
      domain name. This binding significantly reduces the risk of a rogue website impersonating Quick
      Crypt and tricking people into decrypting
      data on that rogue site. Modern browsers will restrict passkey authentication to
      Quick Crypt's own domain name, preventing impersonation.
      Your passkey makes it infeasible for a rogue website to decrypt your data even
      if you exposed your encryption password.
      </p>`
   },

   {
      position: 0,
      question: 'Can I decrypt my data if Quick Crypt goes offline or my account is deleted?',
      answer: `Yes, as long as you have your recovery link. The user credential in
      your recovery link and the password used during encryption are the only inputs
      needed to decrypt data encrypted with Quick Crypt. Other tools can be used
      to decrypt Quick Crypt cipher armor in a multi-step process. If you want to
      be sure someone can recreate Quick Crypt's logic, the code is open source so
      you can <a href="https://github.com/bschick/qcrypt" target="_blank">
      fork away</a> or save the
      <a href="/help/protocol">protocol description</a>. The Quick Crypt source
      repo also contains a
      <a href="https://github.com/bschick/qcrypt/blob/main/qcrypt.ts" target="_blank">
      simple command-line tool</a> that can decrypt Quick Crypt cipher armor at the
      command-line if you have the encryption password and user credential. Install
      dependencies and run:<blockquote>> npx tsx ./qcrypt.ts</blockquote>`
   },

   {
      position: 0,
      question: 'Can I decrypt my data if I forget the password I used for encryption?',
      answer: `There is no way to decrypt data if you forget the
      password used during encryption of that data. Quick Crypts needs both
      the password you used to encrypt the data and a passkey to access your user
      credential. Your recovery link lets you create a new passkey, but there is
      no way to recover a lost password. Consider using a password hint
      next time.`
   },

   {
      position: 0,
      question: 'What should I do if I cannot locate my passkey but have my recovery link?',
      answer: `Paste your recovery link into your browser's address bar and hit enter. Quick
      Crypt will delete all existing passkeys and create a new one for you.`
   },

   {
      position: 0,
      question: 'What happens if I cannot locate my passkey or my recovery link?',
      answer: `If you lost both your Quick Crypt passkeys and recovery link, you cannot
      access your existing user identity to decrypt or encrypt data. This is similar to
      forgetting your encryption password for all previous encryptions. To continue using
      Quick Crypt, you may create a new user identity, but the new user cannot decrypt
      existing cipher text. If you find your original recovery link or passkey later, you
      can use either to regain access to your original user identity anytime.`
   },

   {
      position: 0,
      question: 'Does Quick Crypt store or process Personal Identifiable Information (PII)?',
      answer: `Quick Crypt does not request, collect, or process PII. When you enter a user
      name or a
      passkey description, you may use whatever values you choose. It is best not to use PII
      for those values, but even if you use an email address or personal name Quick Crypt
      treats that as an opaque value and will not contact you. If you change your user name
      or passkey descriptions, previous values are
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
          <td class="tg-0pky">Your unencrypted and encrypted data</td>
          <td class="tg-0pky">Not stored, not transmitted</td>
          <td class="tg-0pky">Only present in browser edit fields.
            Close your browser tab, navigate away, or empty the browser edit fields to remove</td>
        </tr>
        <tr>
          <td class="tg-0pky">Passwords and hints used for encryption and decryption</td>
          <td class="tg-0pky">Not stored, optionally cached, not transmitted</td>
          <td class="tg-0pky">When password caching is enabled within "Advanced Options," the last
            password entered is cached in browser memory. Click the "Flush" button to remove or turn off caching.</td>
        </tr>
        <tr>
          <td class="tg-0pky">Encryption and decryption preferences such as symmetric cipher choice</td>
          <td class="tg-0pky">Browser local storage, not transmitted</td>
          <td class="tg-0pky">Within the "Advanced Options" section on the main page, click the
            "Reset To Defaults" button<br> </td>
        </tr>
        <tr>
          <td class="tg-0pky">Last signed-in user name and user ID</td>
          <td class="tg-0pky">Browser local storage, transmission below</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, click the "Sign Out" button, then click the
            "Sign in as a different user" button</td>
        </tr>
        <tr>
          <td class="tg-0pky">Currently signed-in user credential</td>
          <td class="tg-0pky">Browser sessions storage, transmission below</td>
          <td class="tg-0pky">Close the Quick Crypt tab in your browser or navigate to another website.
          Automatically flushed after 6 hours of inactivity</td>
        </tr>
        <tr>
          <td class="tg-0pky">Public-key portions of each passkey and description</td>
          <td class="tg-0pky">AWS storage service, HTTPS transmission from server to browser</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, click the trash can icon for the passkey
            you want to remove</td>
        </tr>
        <tr>
          <td class="tg-0pky">User name, ID, and credential associated with public-key portions of passkeys</td>
          <td class="tg-0pky">AWS storage service, HTTPS transmission from server to browser</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, delete all passkeys.
          That triggers removal of all server-side data</td>
        </tr>
      </tbody>
    </table>`
   },

   {
      position: 0,
      question: 'Does Quick Crypt store or upload the passwords I use for encryption?',
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
      question: 'Can I use Quick Crypt to encrypt and decrypt files?',
      answer: `Yes, to encrypt a file click the <i>Files</i> button next to the <i>Encrypt</i>
      button and then chose
      <i>Select Clear File</i> from the menu. The selected file may contain text
      or binary data. After you select a file, click the <i>Encrypt</i>
      button or to save the encrypted data to a file, open the Files
      menu again and chose <i>Encrypt to File</i>. To deccrypt a previously encrypted
      file, click the <i>Files</i> button next to the <i>Decrypt</i>
      button and then chose <i>Select Cipher File</i> from the menu.`
   },

   {
      position: 0,
      question: 'Can I use Quick Crypt to send secrets to other people?',
      answer: `<p>Yes, but you should find a better way. Quick Crypt was designed
      to encrypt and decrypt your own data rather than to share data securely
      with others. Decryption with Quick Crypt can be done by someone with both
      the encryption password and a passkey authorizing access to your user
      credential. Passwords are easy to share (although doing so securely is
      not easy), and passkeys can be shared with a good management
      tool like Bitwarden or 1Password. If the recipient has both,
      they can decrypt cipher armor you copy from Quick Crypt and send them.
      But again, there are better ways to do this.`
   },

   {
      position: 0,
      question: 'Can I create more than one passkey or user account?',
      answer: `Yes to both. Once signed in, create additional passkeys
      from the slide-out panel opened with the 3-line button in the toolbar.
      Sign out from the slide-out panel to create a new user
      identity with a new passkey. To reduce the load on Quick Crypt servers,
      please add only as many passkeys and users
      as needed. Identities that look like abuse may be purged.`
   },

   {
      position: 0,
      question: 'How do I delete passkeys?',
      answer: `Once signed in, delete passkeys from the slide-out panel
      opened with the 3-line button in the toolbar. This will remove the
      public-key portion of the paskey from Quick Crypt servers. You must then
      use your local passkey management tool to delete the passkey from your
      system.`
   },

   {
      position: 0,
      question: 'How do I delete my Quick Crypt user identity entirely?',
      answer: `Once signed in, delete all passkeys from the slide-out panel opened
      with the 3-line button in the toolbar. Deleting your last passkey will also
      delete your entire Quick Crypt user identity.
      Once removed, you cannot use Quick Crypt to decrypt data
      with the removed user identity. This is not reversible, even with the recovery
      link. You could use data in the recovery link with other tools to
      decrypt your data (see the related question). Remember to also delete passkeys
      from your system using your local passkey management tool.`
   },


   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained a password I used for encryption?',
      answer: `Your data is still protected.
      The potential attacker also needs your encrypted data and your passkey or recovery link
      to decrypt it.
      Without a passkey or recovery link to access your user credential,
      an attacker cannot decrypt your data. Regardless, the best response to a stolen password
      is to re-encrypt your data with a new password and delete any cipher armor created with
      the stolen password.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained my passkey?',
      answer: `Your data is still protected, but your Quick Crypt user account is at risk.
      The potential attacker would also need your encrypted data and the password you used
      during encryption to decrypt it. Without your encryption password, the attacker
      cannot decrypt your data. Since your passkey allows access to your user credential,
      you should replace the lost passkey. Within Quick Crypt, open the side panel and create
      a new passkey. After confirming that your new passkey works, delete the passkey you
      lost from Quick Crypt and from your passkey management tool. There is no need to
      re-encrypt your data unless someone may have used your
      passkey to sign in and copy your recovery link. If you believe someone used your
      passkey to retrieve your recovery link, see the question about an untrusted person
      obtaining your recovery link.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained my recovery link?',
      answer: `Your data is still protected, but your Quick Crypt user account is at risk.
      The potential attacker would also need your encrypted data and the password you used
      during encryption to decrypt it. Without your encryption password, the attacker cannot
      decrypt your data. However, the person with your recovery link could cause you grief
      by deleting your passkeys or your entire Quick Crypt user account. The best response to a
      stolen recovery link is to create a totally new Quick Crypt user, re-encrypt
      your data, and then delete the previous cipher armor and original user identity.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained my recovery link or passkey and a password I used for encryption?',
      answer: `The potential attacker also needs your encrypted data to decrypt it.
      If the attacker has your encrypted data, your confidential information may be
      exposed. The best response to a stolen
      recovery link or passkey and password is to create a totally
      new Quick Crypt user, re-encrypt your data with a new password, and then delete
      the previous cipher armor and your previous user identity.`
   },

   {
      position: 0,
      question: 'Has threat modeling been done for Quick Crypt?',
      answer: `Only informally, and we'd welcome contributions. These areas have
      been considered:
      <ol type='i'>
         <li><b>Coding errors:</b> We've done our best, but this is always a possible weakness.
         Please <a href="https://github.com/bschick/qcrypt" target="_blank">review the code</a> and
         <a href="https://github.com/bschick/qcrypt/issues" target="_blank">report issues</a>
         you find. Quick Crypt may open a bug bounty program to
         encourage reporting.</li>
         <li><b>Supply chain attacks:</b> This is a growing security issue for all software.
         Quick Crypt tries to limit the surface area of attack by using a small number
         of well-known open-source libraries (and your web browser of choice). See the
         <a href="/help/overview">overview page</a> for a list of third-party package
         dependencies. Quick Crypt bundles all libraries into a 'single-page' web-app.
         Much like a native binary application, dependencies are
         integrated at build time and never downloaded on the fly, better ensuring
         integrity.
         </li>
         <li><b>Various web-app attacks:</b> Quick Crypt uses the latest web-app security
         protocols (csp, cors, modern cert, sri, referrer-policy, hsts, xfo, etc.)
         and aims to maintain an A+ rating at test sites like
         <a href="https://observatory.mozilla.org/analyze/quickcrypt.org" target="_blank">Mozilla Observatory</a>.
         As described above, Quick Crypt bundles all libraries into a
         'single-page' web-app to better ensure integrity.
         </li>
         <li><b>Server-side data theft or logic injection:</b> Quick Crypt uses AWS
         for server-side logic
         and data storage, and has a minimal API. Our AWS account follows best practices
         and uses AWS Config
         and AWS Security Hub to help detect problems. A continuous penetration
         testing tool may be added in the future. Server code is also open-source
         and <a href="https://github.com/bschick/qcrypt-server" target="_blank">
         available for review</a> and
         <a href="https://github.com/bschick/qcrypt-server/issues" target="_blank">
         bug reports</a>.
         </li>
         <li><b>Website impersonation:</b> Several well-known security breaches
         occurred when an untrusted site impersonated a trusted site.
         Since Quick Crypt is an open-source project, an attacker could create
         a site that looks identical and has a similar domain name. Quick Crypt
         dramatically reduces the risk of decrypting data at an untrusted site
         by requiring a server-side user credential only accessible
         with a passkey bound to Quick Crypt's domain. User credentials and passkeys
         make it infeasible for other websites to decrypt your data since
         browsers are not fooled by similar looking websites
         or domain names and will not present a passkey bound to Quick Crypt for another
         website. Quick Crypt cannot prevent you from starting at a similar looking
         untrusted website and entering clear text and passwords, however. The best way
         to reduce that risk is to always confirm your user name is shown at the top of the
         password input popup. You should also navigate directly to https://quickcrypt.org,
         save it as a bookmark, and only follow links from sites you trust.
         </li>
         <li><b>Stolen passkeys, recovery links, or encryption passwords:</b>
         See the related questions about an untrusted user obtaining your
         passkeys, recovery links, or encryption passwords. Those questions describe
         the best response to each type of data exposure.
         </li>
      </ol>`
   },

   {
      position: 0,
      question: 'How should I decide which cipher mode to use?',
      answer: `Quick Crypt offers only well-established and tested
      <a href="https://en.wikipedia.org/wiki/Authenticated_encryption" target="_blank">
      AEAD cipher modes</a> that provide privacy and authenticity: AES 256 GCM,
      XChaCha20 Poly1305, and AEGIS 256. No mode is bad, and choosing one depends on
      your criteria.
      <ul>
         <li>If you want the most recently designed cipher mode, choose <b>AEGIS 256</b>.
         </li>
         <li>If you want the most widely used and studied mode, choose <b>AES 256 GCM</b>,
         which is the most commonly used TLS 1.3 cipher used by most browsers.
         <li>If you want a mode that many regard as more robust than AES 256 GCM and
         whose close sibling is in the TLS 1.3 standard, choose <b>XChaCha20 Poly130</b>.
         </li>
         <li>If you want the smallest resulting cipher armor (although not by much),
         choose <b>AES 256 GCM</b> first, then <b>XChaCha20 Poly1305</b>, and <b>AEGIS 256</b>
         last.
         </li>
         <li>If you want a mode implemented by your browser vendor, choose <b>AES 256 GCM</b>.
         </li>
         <li>If you want a mode that runs in your browser but is implemented by the open-source
         <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a>,
         choose <b>XChaCha20 Poly1305</b> or <b>AEGIS 256</b>
         </li>
         <li>While there is no universal agreement on the "safest" mode, the
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead#tl-dr-which-one-should-i-use" target="_blank">
         libsodium project recommends</a> <b>AEGIS 256</b> first, then <b>XChaCha20 Poly1305</b>,
         and <b>AES 256 GCM</b> last.
         </li>
      </ul>
      <p>Quick Cyrpt defaults to <b>XChaCha20 Poly1305</b> because it is very
      well-established and believed to be more robust than AES 256 GCM. The
      libsodium implementation is also easy for Quick Crypt to update if needed.
      </p>`
   },

   {
      position: 0,
      question: "What are the 'True Random' and 'Pseudo Random' options?",
      answer: `<p>Random values are input to cryptographic functions as salts and
      nonces/initialization vectors and must be generated in a manner
      <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator" target="_blank">
      suitable for use in cryptography</a>. Quick Crypt uses WebCrypto
      <a href="https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues" target="_blank">getRandomValues()</a>
      by default, which generates cryptographically strong pseudo-random algorithmic values.
      Unlike other
      cryptographic functions implemented by browsers, however, random number generation
      is not standardized and quality may vary. You can alternatively configure Quick
      Crypt to download random data generated from atmospheric noise by
      <a href="https://www.random.org" target="_blank">https://www.random.org</a>, which
      should be closer to true random data. This option is set within the "Advanced
      Options" section on the main page. When you enable the 'True Random'
      option, you can optionally enable your browser's 'Pseudo Random' function
      as a fallback if random.org is unreachable. If random.org is unreachable and
      'Pseudo Random' is disabled, encryption operations result in an error.</p>
      <p>Quick Crypt generates or downloads new random values for every encryption,
      meaning nonces and salts are never reused, and every encryption key should be
      unique. For details about how random values are used, refer to Quick
      Crypt's <a href="/help/protocol">protocol description</a>.</p>`
   },

   {
      position: 0,
      question: "What is the 'Check if Stolen' option?",
      answer: `When you enable the 'Check if Stolen' option, Quick Crypt checks
      an online database from
      <a href="https://haveibeenpwned.com/API/v2#PwnedPasswords" target="_blank">https://haveibeenpwned.com</a>
      for passwords that have been leaked or stolen, and prevents you from using
      them for encryption. Attackers compile leaked passwords into lists to speed up
      password guessing. Quick Crypt uses large variable numbers of PBKDF2 key
      derivation iterations and combines your encryption password with a
      passkey-protected user credential to make password guessing extremely difficult,
      even with leaked passwords. But it is always better to use a strong password
      for defense-in-depth.`
   },

   {
      position: 0,
      question: 'I have read that web applications should not be trusted for cryptography.',
      answer: `That's not a question! Much has changed over the past decade, making web
      security protocols and browsers more robust and trustworthy. Bundled single-page
      applications combined with standards like CSP, CORS, HSTS, Referrer Policy, SRI,
      XFO, and Passkey (webauthn) make web applications trustworthy. Of course, web
      standards and tools are imperfect, but so are installed binary applications
      (see Linux xz). Perhaps a longer write-up is warranted someday.`
   },

   {
      position: 0,
      question: 'Can Quick Crypt decrypt cipher text created by other tools?',
      answer: `No, Quick Crypt was not designed to interoperate with cipher text
      from other tools. Quick Crypt's goals are described on the
      <a href="/help/overview">overview page</a>`
   },

   {
      position: 0,
      question: 'Can other tools decrypt cipher text created by Quick Crypt?',
      answer: `Yes, as long as you save your recovery link, remember your
      encryption password, and follow
      <a href="/help/protocol">Quick Crypt's protocol</a>, you could use other
      tools to decrypt cipher text created by Quick Crypt in a multi-step process.
      Those steps aren't documented yet, but are fairly easy to figure out.`
   },

   {
      position: 0,
      question: 'What are the different Cipher Armor formats?',
      answer: `<p>Cipher Armor is text that includes encrypted
      data and parameters (called cipher text) combined with metadata
      about the cipher text. The 'Compact'
      and 'Indent' formats are JSON containing the same elements
      with different spacing and line breaks. As the names imply, the
      'Compact' format is smaller while 'Indent' is easier to read.</p>
      <p>
      The 'Link' format is a URL containing cipher text that when entered in
      a browser, takes you directly to the Quick Crypt website with the cipher
      text ready for decryption. While this is very convenient, the 'Link'
      format is less safe. If an attacker can manipulate your stored cipher armor
      URL, they could edit the domain name and send you to an untrusted website.
      This is possible because the domain portion of a URL cannot be encrypted or
      validated and still be usable in a browser. Because an untrusted site cannot
      access your Quick Crypt passkey, however, it cannot obtain authorization to
      access your user name or credential nor can it decrypt your data (see the
      'threat modeling' question). An untrusted site could request your encryption
      password to try obtaining some of the information needed for decryption, but
      you can detect that by always confirming your user name is
      shown at the top of the password prompt.</p>

      <p>Opting for the 'Compact' or 'Indent' cipher armor formats and
      navigating directly to Quick Crypt's website is the safest choice.
      The 'Link' format can be used when you are not concerned about anyone
      changing stored cipher armor. All three formats provide strong
      privacy and authenticity.</p>`
   },

   {
      position: 0,
      question: 'What does the Loop Encrypt option do?',
      answer: `<p>By default, Quick Crypt encrypts your plain text or file once.
      If you set Loop Encrypt to be greater than 1,
      Quick Crypt encrypts your data that many times. For example, if you
      set Loop Encrypt to 3, there will be 3 encryption steps:
      <ol type='1'>
         <li>Your plain text or file is encrypted</li>
         <li>The encrypted data from loop 1 is encrypted</li>
         <li>The encrypted data from loop 2 is encrypted</li>
      </ol>
      The encrypted data resulting from loop 3 is then output as Cipher
      Armor or saved to a file. The saved data contains the number of loops
      to simplify decryption.
      </p>
      <p>Loop encryption only provides improved security and privacy when
      you enter a different password for each loop (other encryption options
      cannot currently be changed between loops). If you forget any one of the
      passwords you used while looping, you will not be able decrypt the
      Cipher Armor.</p>`
   },

   {
      position: 0,
      question: 'How is data encrypted and decrypted, and which crypto implementations are used?',
      answer: `<p>See the detailed description on the
      <a href="/help/protocol">protocol help page</a>.</p><p>
      Quick Crypt uses well-established cryptographic functions available in modern browsers.
      All cryptographic functions are run in your browser, ensuring your data remains local.
      The primary cryptographic functions are listed below. <i>SubtleCrypto</i>
      means the function is implemented by your browser's (Chrome, Safari, Edge, etc)
      <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto" target="_blank">
      SubtleCrypto API</a>. <i>Libsodium</i> means
      the function is implemented by the open-source
      <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a> bundled into
      the Quick Crypt web-app.</p>
      <ol type='i'>
         <li class="long"><b>Random Values:</b> WebCrypto <a href="https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues"
         target="_blank">getRandomValues()</a><br/>or <a href="https://www.random.org"
         target="_blank">https://www.random.org/cgi-bin/randbyte</a>
         </li>
         <li><b>HKDF and PBKDF2 Key Derivation:</b> SubtleCrypto
         <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey" target="_blank">deriveKey()</a>
         </li>
         <li><b>AES 256 GCM Cipher:</b> SubtleCrypto <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt"
         target="_blank">encrypt()</a> and
         <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt" target="_blank">decrypt()</a>
         </li>
         <li class="long"><b>XChaCha20 Poly1305 Cipher:</b> libsodium
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction"
         target="_blank">crypto_aead_xchacha20poly1305_ietf_encrypt()</a> <br/>and
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction"
         target="_blank">crypto_aead_xchacha20poly1305_ietf_decrypt()</a>
         </li>
         <li class="long"><b>AEGIS 256 Cipher:</b> libsodium <a href="https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256"
         target="_blank">crypto_aead_aegis256_encrypt()</a> and<br/>
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256"
         target="_blank">crypto_aead_aegis256_decrypt()</a>
         </li>
         <li><b>BLAKE2b Keyed Hash:</b> libsodium <a href="https://doc.libsodium.org/hashing/generic_hashing"
         target="_blank">crypto_generichash()</a>
         </li>
      </ol>`
   },

   {
      position: 0,
      question: 'Can I use Quick Crypt without entering encryption passwords?',
      answer: `<p>Quick Crypt always requires passwords to encrypt or decrypt data.
      Quick Crypt does have a password strength option, however, that can be set
      to 'terrible' requiring only one character passwords. Since passwords are
      always combined with a much longer user credential accessed with
      passkey authentication, a weak password is not as insecure as it may sound. We
      designed Quick Crypt so that weak passwords or overly descriptive hints
      only reduce security to the strength of passkey authentication, which is
      trusted by many top websites. This design aligns with
      Quick Crypt's goal of making it hard to screw up.</p>
      <p>Regardless, using strong passwords is always more secure than using
      weak passwords. Rather than use weak passwords, you should use strong
      passwords along with password hints that help only you remember them.</p>`
   },

   {
      position: 0,
      question: 'What key lengths does Quick Crypt use?',
      answer: `Symmetric cipher keys are 256 bits long and derived
      from the password you enter during encryption combined with your user
      credential that is accessed with passkey authentication. MAC keys
      are 256 bits long and derived from your user credential. For more details,
      see the <a href="/help/protocol">protocol description</a> help page.`
   },

   {
      position: 0,
      question: 'Are my password hints encrypted?',
      answer: `Yes, password hints are encrypted with a key derived from
      your user credential that is accessed with passkey authentication.
      For the most robust protection of your secret information, avoid
      hints that make it easy for others to guess your encryption password.
      The best password hints help only you remember the password.
      That way, you are protected even if your passkey or recovery link
      is stolen.`
   },

   {
      position: 0,
      question: 'Why is XChaCha20 offered rather than IETF ChaCha20?',
      answer: `Quick Crypt uses random nonce values for cipher initialization
      vectors, and XChaCha20 is safer than ChaCha20 with random nonce values
      (although since Quick Crypt never reuses nonce values or cipher keys, ChaCha20
      could still be suitable). IETF ChaCha20's one advantage is standardization,
      but since interoperability with other tools was not a Quick Crypt goal,
      XChaCha20 was selected as a better overall cipher mode.`
   },

   {
      position: 0,
      question: 'Why does Quick Crypt use both MACs and AEAD ciphers?',
      answer: `This was done for defense-in-depth and so Quick Crypt
      can safely load and display metadata like password hints before the
      decryption algorithm runs. Imagine an attacker could modify your
      encrypted data and knows of a bug in Chrome's AES GCM cipher. Although
      unlikely, that might allow an attacker to craft the cipher text such
      that data was leaked when you decrypted it. The additional MAC (BLAKE2b
      keyed hash) validation means there would need to be problems with
      both the libsodium generated MAC and the browser or libsodium cipher
      algorithm for such an attack to succeed, which is even more unlikely.`
   },

   {
      position: 0,
      question: 'What will Quick Crypt do if one of the current cipher modes is broken?',
      answer: `If any of the three cipher modes used by Quick Crypt are someday
      found to be weak, Quick Crypt will stop offering those modes as an option for
      encryption. Problematic ciphers would only be available for decryption so
      users can access already encrypted data. Depending upon the
      severity of the weakness, Quick Crypt would notify users of the situation on
      this site (remember we have no contact info) and recommend that you re-encrypt
      data using a different cipher mode. Such a weakenss would be massive news
      since two modes are part of the TLS 1.3 standard used by most browsers,
      and the third is proposed for a future TLS version.`
   },
];