import { AfterViewInit, Component, ViewEncapsulation } from '@angular/core';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { animate, state, style, transition, trigger } from '@angular/animations';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { HttpParams } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CopyrightComponent } from "../../ui/copyright/copyright.component";


export interface FAQElement {
   position: number;
   question: string;
   answer: string;
}

@Component({
    selector: 'app-faqs',
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
    CopyrightComponent
]
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
      question: 'Who can decrypt the data I encrypt with Quick Crypt?',
      answer: `To decrypt data encrypted with Quick Crypt, you need both the
      password you used for encryption and a passkey restricting access to your
      Quick Crypt user credential. Unless you share your passkey and encryption
      password with someone, only you can decrypt data that you have encrypted.`
//      This is true for self-encrypted data and data encrypted for you through
//      a sender link. The Quick Crypt web app does not store your passwords and
//      therefore cannot decrypt your data. Do not forget the passwords you use
 //     for encryption.`
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
      <p>Although passkeys can operate without passwords, Quick Crypt uses both passwords
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
      question: 'Can I decrypt my data if the Quick Crypt site goes offline?',
      answer: `Yes, as long as you have your user credential and the password
      you used during encryption. You can get your user credential by
      navigating to https://quickcrypt.org/cmdline. The user credential and the
      password you used during encryption are the only inputs
      needed to decrypt Quick Crypt ciphertext. The website is not
      required. There is a
      command-line tool that decrypts Quick Crypt cipher armor. Download the
      <a href="https://github.com/bschick/qcrypt/tree/main/shell" target="_blank">qcrypt.cjs</a>
      file, install <a href="https://nodejs.org/" target="_blank">Node.js</a>,
      , and run the script from the command-line:
      <blockquote>> node qcrypt.cjs</blockquote>
      <p>Other tools could also be used to decrypt Quick Crypt cipher armor in a
      multi-step process. If you want to be sure someone can recreate Quick Crypt's
      logic, the code is <a href="https://github.com/bschick/qcrypt" target="_blank">
      open source</a>, and you have the
      <a href="/help/protocol">protocol description</a>.</p>`
   },

   {
      position: 0,
      question: 'Can I decrypt my data without an internet connection?',
      answer: `<p>Yes, as long as you have already signed into Quick Crypt.
      After signing in, Quick Crypt runs entirely in your browser and does not
      require an internet connection to decrypt or encrypt data.  If you are
      inactive for 1.5 hours, however, Quick Crypt logs you out and then requires
      an internet connection to sign in again and decrypt data.</p>
      <p>The Quick Crypt command-line tool is another option that never
      requires an internet connection once installed. You need your user credential
      and the password you used during encryption. You can get your user credential
      by navigating to https://quickcrypt.org/cmdline. Then download the
      <a href="https://github.com/bschick/qcrypt/tree/main/shell" target="_blank">qcrypt.cjs</a>
      file and install <a href="https://nodejs.org/" target="_blank">Node.js</a>
      before going offline. Then
      run the script from the command-line and respond to the prompts:
      <blockquote>> node qcrypt.cjs</blockquote>.</p>`
   },

   {
      position: 0,
      question: 'Is there a command-line version of Quick Crypt?',
      answer: `Yes, there is a command-line tool that can decrypt, encrypt, and
      show cipher data information on your system without
      accessing the Quick Crypt website. To use the command-line tool to decrypt
      data, you need your user credential and the password
      you used during encryption. You can get your user credential by
      navigating to https://quickcrypt.org/cmdline. Then
      <a href="https://github.com/bschick/qcrypt/tree/main/shell" target="_blank">
      download the qcrypt.cjs file</a>, ensure you have
      <a href="https://nodejs.org/" target="_blank">Node.js</a> installed, and
      then run the tool from the command-line and respond to the prompts:
      <blockquote>> node qcrypt.cjs</blockquote>.`
   },

   {
      position: 0,
      question: 'Can I decrypt my data if I forget the password I used for encryption?',
      answer: `There is no way to decrypt data if you forget the
      password used during encryption. Quick Crypt requires both
      the password you used to encrypt the data and a passkey to access your user
      credential. Your recovery word pattern lets you create a new passkey, but there is
      no way to recover a lost password. Consider using a password hint
      to help remember your password.`
   },

   {
      position: 0,
      question: 'What should I do if I cannot locate my passkey but have my recovery word pattern?',
      answer: `Go to Quick Crypt's <a href="/recovery2">account recovery</a> page and
      enter your recovery word pattern. Start the recovery process and Quick
      Crypt will delete all existing passkeys and create a new one for you.`
   },

   {
      position: 0,
      question: 'What happens if I cannot locate my passkey or my recovery word pattern?',
      answer: `If you lost both your Quick Crypt passkeys and recovery word pattern, you cannot
      access your existing user identity to decrypt or encrypt data. This is similar to
      forgetting your encryption password for all previous encryptions. To continue using
      Quick Crypt, you may create a new user identity, but the new user cannot decrypt
      existing ciphertext. If you find your original recovery word pattern or passkey
      later, you can use either to regain access to your original user identity.`
   },
/*
   {
      position: 0,
      question: 'What is a sender link and how do I use it?',
      answer: `<p>A sender link allows other to encrypt text or files that only you can
      decrypt without exposing your credentials. You specify how many times a each
      sender link can be used and when the link will expire. Once created, you can give
      the sender link to others who can use it to encrypt data only you can decrypt.
      Recipients should follow the link and encrypt data with passwords just as they
      would normally in Quick Crypt. Recipients may then send you the encrypted
      data by any means they chose (message app, email, file sharing, etc). Neither
      unencrypted nor encrypted data is processed, sent, or stored by Quick Crypt
      servers, ensuring you maintain full control over the information provided by
      the sender. When you
      receive encrypted data, you decrypted it as you would normally in Quick Crypt
      with the same strong privacy and authenticity characteristics.</p>
      <p>

      </p>

       To create a sender link, click the "Sender Link" button on the main page.`
   },


   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtains a sender link I created?',
      answer: `<p>First, it is important to understand that sender links can only encrypt data.
      When someone has a sender link you created, they cannot use it to decrypt your data nor
      even the resulting cipher armor they creating themselves using your link.</p>
      <p>
      If an untrusted person has a sender link you created they could use it to encrypt data
      you don't want or trust. There are several ways to handle this situation:
      <ol type='i'>
      <li>Delete the sender link on <a href="/help/overview">Quick Crypt's sender like page</a></li>
      <li>Quick Crypt helps you detect lost sender links by showing you the
      user name from the account who encrypted data. If you did not expect data from that
      sender, you should not trust it</li>
      <li>Since Quick Crypt never stores or sends encrypted data, you can also confirm you received
      encrypted data from an expected sender (email address, messaging user, etc.)</li>
      </ol>

      </p>


      does not allow
      other to decrypt your data. Sender links can only be used to encrypt data, and others
      uho use your sender link cannot even decrypt that data themselves.

      A sender link allows other to encrypt text or files that only you can
      decrypt without exposing your credentials. You specify how many times a each
      sender link can be used and when the link will expire. Once created, you can give
      the sender link to others who can use it to encrypt data only you can decrypt.
      Recipients should follow the link and encrypt data with passwords just as they
      would normally in Quick Crypt. Recipients may then send you the encrypted
      data by any means they chose (message app, email, file sharing, etc). Neither
      unencrypted nor encrypted data is processed, sent, or stored by Quick Crypt
      servers, ensuring you maintain full control over the information provided by
      the sender. When you
      receive encrypted data, you decrypted it as you would normally in Quick Crypt
      with the same strong privacy and authenticity characteristics.</p>
      <p>

      </p>

       To create a sender link, click the "Sender Link" button on the main page.`
   },
*/

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
          <td class="tg-0pky">Cryptographic keys for encryption and decryption</td>
          <td class="tg-0pky">Not stored, not transmitted</td>
          <td class="tg-0pky">Cryptographic keys are ephemeral, generated on the fly, and discarded after each use.</td>
        </tr>
        <tr>
          <td class="tg-0pky">Encryption and decryption preferences such as symmetric cipher choice</td>
          <td class="tg-0pky">Browser local storage, not transmitted</td>
          <td class="tg-0pky">Within the "Advanced Options" section on the main page, click the
            "Reset To Defaults" button<br> </td>
        </tr>
        <tr>
          <td class="tg-0pky">Last signed-in user name and user ID</td>
          <td class="tg-0pky">Browser local storage, HTTPS transmission from server to browser</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, click the "Sign Out" button, then click the
            "Sign in as a different user" button</td>
        </tr>
        <tr>
          <td class="tg-0pky">Currently signed-in user credential</td>
          <td class="tg-0pky">Browser memory, HTTPS transmission from server to browser</td>
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
          <td class="tg-0pky">User name and ID associated with public-key portions of passkeys</td>
          <td class="tg-0pky">AWS storage service, HTTPS transmission from server to browser</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, delete all passkeys.
          That triggers removal of server-side stored data</td>
        </tr>
        <tr>
          <td class="tg-0pky">User credential and recovery Id associated with public-key portions of passkeys</td>
          <td class="tg-0pky">Encrypted AWS storage service, HTTPS transmission from server to browser</td>
          <td class="tg-0pky">Within the side panel that shows passkeys, delete all passkeys.
          That triggers removal of server-side stored data</td>
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
      question: 'Does Quick Crypt use browser cookies?',
      answer: `Quick Crypt uses a single, secure
      cookie to create a session between your browser and our servers. The session
      allows you to open new tabs or make account changes without reauthorizing
      each action. Data encryption and decryption are performed locally in your
      browser and do not use cookies, sessions, or exchange data with our servers.
      <ul>
         <li><b>No Tracking or Advertising: </b>We do not use any third-party cookies.
         Your activity is not tracked and we do not have advertisers.
         </li>
         <li><b>Session Cookie: </b>We use a single, first-party cookie exclusively
         to keep you logged in. Each session has a unique cookie.
         </li>
         <li><b>Cookie Security: </b>Our session cookies are HttpOnly and implemented as
         server-signed JSON Web Tokens (JWTs) using account and session-specific keys,
         protecting you from attacks like cross-site scripting.
         </li>
         <li><b>Limited Duration: </b>A session automatically expires after either 1.5
         hours of inactivity or 3 hours of elapsed time.
         </li>
         <li><b>Clean Logout: </b>The cookie is deleted from your browser and invalidated
         server-side when you log out or your session expires.
         </li>
      </ul>`
   },

   {
      position: 0,
      question: 'Can I use Quick Crypt to encrypt and decrypt files?',
      answer: `Yes, to encrypt a file click the <i>Files</i> button next to the <i>Encrypt</i>
      button and then choose
      <i>Select Clear File</i> from the menu. The selected file may contain text
      or binary data. After you select a file, click the <i>Encrypt</i>
      button or to save the encrypted data to a file, open the Files
      menu again and choose <i>Encrypt to File</i>. To decrypt a previously encrypted
      file, click the <i>Files</i> button next to the <i>Decrypt</i>
      button and then choose <i>Select Cipher File</i> from the menu.
      <p>You can inspect the layout of encrypted data within a Quick Crypt file by
      adding this <a href="/assets/quickcrypt.tcl" download>template file</a> to the
      <a href='https://hexfiend.com/' target="_blank">Hex Fiend</a> macOS application.
      </p>`
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
      public-key portion of the passkey from Quick Crypt servers. You must then
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
      with the removed user identity. This is not reversible, even with your recovery
      word pattern. Remember to also delete passkeys
      from your system using your passkey management tool.`
   },


   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained a password I used for encryption?',
      answer: `Your data is still protected.
      The potential attacker also needs your encrypted data and your passkey or
      recovery word pattern to decrypt it.
      Without a passkey or recovery word pattern to access your user credential,
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
      passkey to sign in to Quick Crypt. If you believe someone used your passkey to sign
      in, see the question about an untrusted person obtaining your recovery word pattern.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained my recovery word pattern?',
      answer: `Your data is still protected, but your Quick Crypt user account is at risk.
      The potential attacker would also need your encrypted data and the password you used
      during encryption to decrypt it. Without your encryption password, the attacker cannot
      decrypt your data. However, the person with your recovery word pattern could cause you
      grief by replacing your passkeys or deleting your entire Quick Crypt user account,
      preventing you from decrypting your own data. The
      best response to a stolen recovery word pattern is to create a totally new Quick Crypt
      user, re-encrypt your data, and then delete the previous cipher armor and original user
      identity.`
   },

   {
      position: 0,
      question: 'What should I do if someone I don\'t trust obtained my recovery word pattern or passkey and a password I used for encryption?',
      answer: `The potential attacker also needs your encrypted data to decrypt it.
      If the attacker has your encrypted data, your confidential information may be
      exposed. The best response to a stolen recovery word pattern or passkey along
      with an encryption password is to create a totally new Quick Crypt user, re-encrypt
      your data with a new password, and then delete
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
         <a href="https://github.com/bschick/qcrypt/issues" target="_blank">report issues</a>.
         Quick Crypt may open a bug bounty program to encourage reporting.</li>
         <li><b>Protocol design flaws:</b>
         Much like code reviews, we appreciate reviews of the
         <a href="/help/protocol">Quick Crypt protocol</a>. Please
         <a href="https://github.com/bschick/qcrypt/issues" target="_blank">report issues</a>.
         We are also planning to engage third party auditors to review Quick Crypt's protocol
         and will publish the results.</li>
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
         for server-side logic, data storage, encryption at rest, and has a minimal API.
         Our AWS account follows best practices and uses AWS Config
         and AWS Security Hub to help detect problems. Sensitive data is encrypted
         at rest using AWS FIPS 140-3 Level 3 HSMs. A continuous penetration
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
         or domain names and will not present a passkey bound to https://quickcrypt.org
         to another
         website. Quick Crypt cannot prevent you from entering cleartext and passwords
         at a similar looking untrusted website however. The best way
         to reduce that risk is to always confirm your user name is shown at the top of the
         password input popup. You should also navigate directly to https://quickcrypt.org,
         save it as a bookmark, and only follow links from sites you trust.
         </li>
         <li><b>Stolen passkeys, recovery word pattern, or encryption passwords:</b>
         See the related questions about an untrusted user obtaining your
         passkeys, recovery word pattern, or encryption passwords. Those questions describe
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
         <li>If you want the most recently designed cipher mode, that is key-committing
         even without Quick Crypt's additional BLAKE2b keyed hash, choose <b>AEGIS 256</b>.
         </li>
         <li>If you want the most widely used and studied mode, choose <b>AES 256 GCM</b>,
         which is the most commonly used TLS 1.3 cipher in browsers.
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
         <li>If you want an implementation designed to resist side-channel attacks, choose
         either <b>XChaCha20 Poly1305</b> or <b>AEGIS 256</b>, which are provided by libsodium
         </li>
         <li>While there is no universal agreement on the "safest" mode, the
         <a href="https://doc.libsodium.org/secret-key_cryptography/aead#tl-dr-which-one-should-i-use" target="_blank">
         libsodium project recommends</a> <b>AEGIS 256</b> first, then <b>XChaCha20 Poly1305</b>,
         and <b>AES 256 GCM</b> last.
         </li>
      </ul>
      <p>Quick Cyrpt defaults to <b>XChaCha20 Poly1305</b> because it is very
      well-established and generally considered more robust than AES 256 GCM. The
      libsodium implementation is also designed to be side-channel attack resistant,
      is key-committing when paired with Quick Crypt's extra MAC tag, and
      is easy for Quick Crypt to update if needed.
      </p><p>For increased protection, you can encrypt your data multiple times
      by setting loop encrypt in the "Advanced Options" section to greater than 1.
      Each loop shoud use a different cipher mode and password. So rather than
      choosing between your browser's AES 256 GCM implementation and libsodium's
      XChaCha20 Poly1305, for example, you can apply both.</p>`
   },

   {
      position: 0,
      question: "How does Quick Crypt generate random values?",
      answer: `<p>Random values are input to cryptographic functions as salts and
      nonces/initialization vectors and must be generated in a manner
      <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator" target="_blank">
      suitable for use in cryptography</a>. Quick Crypt uses libsodium's
      <a href="https://doc.libsodium.org/generating_random_data" target="_blank">randombytes_buf()</a>
      function, which produces cryptographically strong pseudo-random algorithmic values.
      Libsodium was selected over WebCrypto's getRandomValues() function because, unlike
      other WebCrypto functions, random data generation is not standardized, and quality
      may vary. Libsodium uses documented operating system features to generate random data
      that are suitable for creating secret keys.</p>
      <p>Quick Crypt generates new random values for every encryption,
      meaning nonces and salts are never reused, and every encryption key will be
      unique. Refer to Quick
      Crypt's <a href="/help/protocol">protocol description</a> for details about
      random value usage.</p>`
   },

   {
      position: 0,
      question: "What do the 'Password Handling' Advanced Options do?",
      answer: `<p>Quick Crypt uses many PBKDF2-HMAC-SHA512 key
      derivation iterations and combines your password with a
      passkey-protected user credential to make password guessing extremely difficult,
      even with leaked passwords. But it is always better to use a strong password
      for defense-in-depth.</p>
      <p><b>Hash Iterations</b> specifies the number of times the PBKDF2-HMAC-SHA512 algorithm will
      apply a SHA-512 HMAC function to your password and user credential to generate an
      encryption key. Quick Crypt
      selects the default iteration count by benchmarking your system to find the largest
      value that will complete in 500ms. To help ensure strong keys, Quick Crypt accepts a
      minimum of 420,000 and a maximum of 4,294,000,000 iterations.</p>
      <p><b>Minimum Strength</b> sets the required strength for encryption passwords you
      enter. Quick Crypt uses algorithms running in your browser to estimate the strength
      of your password. Entries that are below the required strength are rejected.</p><p>
      <b>Check if Stolen</b> causes Quick Crypt to also check an online database from
      <a href="https://haveibeenpwned.com/API/v2#PwnedPasswords" target="_blank">https://haveibeenpwned.com</a>
      for passwords that have been leaked or stolen, and prevents you from using
      them for encryption. Attackers compile leaked passwords into lists to speed up
      password guessing.</p>`
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
      question: 'Can Quick Crypt decrypt ciphertext created by other tools?',
      answer: `No, Quick Crypt was not designed to interoperate with ciphertext
      from other tools. Quick Crypt's goals are described on the
      <a href="/help/overview">overview page</a>`
   },

   {
      position: 0,
      question: 'Can other tools decrypt ciphertext created by Quick Crypt?',
      answer: `Yes, as long as you copy your user credential from
      https://quickcrypt.org/cmdline, remember your encryption password, and follow
      <a href="/help/protocol">Quick Crypt's protocol</a>, you could use other
      tools to decrypt ciphertext created by Quick Crypt in a multi-step process.`
   },

   {
      position: 0,
      question: 'What are the different Cipher Armor formats?',
      answer: `<p>Cipher armor is text that includes encrypted
      data and parameters (called ciphertext) combined with metadata
      about the ciphertext. The 'Compact'
      and 'Indent' formats are JSON containing the same elements
      with different spacing and line breaks. As the names imply, the
      'Compact' format is smaller while 'Indent' is easier to read.</p>
      <p>
      The 'Link' format is a URL containing ciphertext that when entered in
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
      shown at the top of the password popup.</p>

      <p>Opting for the 'Compact' or 'Indent' cipher armor formats and
      navigating directly to Quick Crypt's website is the safest choice.
      The 'Link' format can be used when you are not concerned about anyone
      changing stored cipher armor. All three formats provide strong
      privacy and authenticity.</p>`
   },

   {
      position: 0,
      question: 'What does the "Loop Encrypt" Advanced Option do?',
      answer: `<p>Loop encryption can improve privacy and authenticity.
      By default, Quick Crypt encrypts your data once.
      If you set Loop Encrypt to be greater than 1, Quick Crypt encrypts your
      data that many times, allowing you to specify a different cipher
      mode and password for each loop. For example, if you
      set Loop Encrypt to 3, there will be 3 encryption steps:
      <ol type='1'>
         <li>Your data is encrypted with cipher mode-1 and password-1</li>
         <li>The encrypted data from loop-1 is encrypted with mode-2 and password-2</li>
         <li>The encrypted data from loop-2 is encrypted with mode-3 and password-3</li>
      </ol>
      The encrypted data from the last loop is output as cipher armor or saved to a file
      and contains the number of loops and cipher modes to simplify decryption.
      </p>
      <p>Loop encryption provides improved security only when
      you use a different cipher mode and password for each loop (other encryption
      options cannot yet be changed between loops). Cipher modes are stored
      within the cipher armor of each loop, but if you forget any of the
      passwords you used while looping, you will not be able to retrieve your
      original data.</p>`
   },

   {
      position: 0,
      question: 'How is data encrypted and decrypted, and which crypto implementations are used?',
      answer: `<p>See the detailed description on the
      <a href="/help/protocol">protocol help page</a>.</p><p>
      Quick Crypt uses well-established cryptographic functions available in modern browsers.
      All cryptographic functions are run in your browser, ensuring your data remains local.
      The primary cryptographic functions are listed below. <i>SubtleCrypto</i>
      means the function is implemented by your browser's
      <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto" target="_blank">
      SubtleCrypto API</a>. <i>Libsodium</i> means
      the function is implemented by the open-source
      <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a> bundled into
      the Quick Crypt web-app.</p>
      <ol type='i'>
         <li class="long"><b>Random Values:</b> libsodium
         <a href="https://doc.libsodium.org/generating_random_data" target="_blank">randombytes_buf()</a>
         </li>
         <li><b>BLAKE2b-512 Key Derivation Function:</b> libsodium
         <a href="https://libsodium.gitbook.io/doc/key_derivation#deriving-keys-from-a-single-high-entropy-key" target="_blank">crypto_kdf_derive_from_key()</a>
         </li>
         <li><b>PBKDF2-HMAC-SHA512 Password Key Derivation:</b> SubtleCrypto
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
      answer: `<p>Quick Crypt requires a password to encrypt or decrypt data. You can
      configure the required password strength in "Advanced Options" to meet your needs.
      For the best security, always use a strong password with a hint that only helps
      you remember it instead of resorting to a weak password. To help, Quick Crypt
      indicates the strength of each password you enter.`
   },

   {
      position: 0,
      question: 'What key lengths does Quick Crypt use?',
      answer: `Symmetric cipher keys are ephemeral, 256 bits long, and derived
      from the password you enter during encryption combined with your user
      credential which is accessed with passkey authentication. MAC keys
      are ephemeral, 256 bits long, derived from your user credential. For more details,
      see the <a href="/help/protocol">protocol description</a> help page.`
   },

   {
      position: 0,
      question: 'Are my password hints encrypted?',
      answer: `Yes, password hints are encrypted with a key derived from
      your user credential which is accessed with passkey authentication. Although
      others cannot see your password hints without your passkey,
      for the most robust protection avoid hints that make it easy for others to
      guess your passwords.
      The best password hints help only you remember your passwords. That way,
      your data is protected even if your passkey or recovery word pattern
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
      answer: `First, by adding a distinct BLAKE2b keyed hash generated with
      a key derived from the same key material as the primary encryption key,
      Quick Crypt's protocol is <href="https://en.wikipedia.org/wiki/Authenticated_encryption#Key-committing_AEAD"
      target="_blank">key-committing</a> for all underlying AEAD
      cipher modes. Second, Quick Crypt can safely read and display unencrypted
      metadata, such as the version number, before the primary decryption algorithm
      runs. And finally, the additional MAC provides defense-in-depth. Imagine an
      attacker could modify your encrypted data and knows of a bug in Chrome's
      AES-GCM cipher. Although unlikely, this might allow an attacker to craft the
      ciphertext such that data is leaked when you decrypt it. The additional MAC
      validation means that there would need to be problems with both the libsodium
      generated BLAKE2b MAC and Chrome's AES cipher implementation for such an attack
      to succeed, which is even less likely.`
   },

   {
      position: 0,
      question: 'Are Quick Crypt\'s algorithms side-channel attack resistant?',
      answer: `Quick Crypt uses algorithms implemented by the open-source
      <a href="https://doc.libsodium.org/" target="_blank">libsodium library</a> and
      your browser's <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto" target="_blank">
      SubtleCrypto API</a>. Libsodium was designed and reviewed to provide side-channel
      attack resistant functions, and Quick Crypt uses these whenever possible. For example,
      constant-time comparison functions test secure values. SubtleCrypto, however, makes
      no explicit claims about side-channel resistance. If this is a concern, you may
      choose either the XChaCha20 Poly1305 or AEGIS 256 modes implemented
      in libsodium rather than the AES 256 GCM mode from SubtleCrypto.`
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

   {
      position: 0,
      question: "What does the 'Decryption Reminder' Advanced Option do?",
      answer: `When enabled, this option adds text to JSON cipher armor that reminds
      you where to decrypt the cipher armor. Quick Crypt does not use this text; It
      is just a reminder for anyone who may forgotten how the cipher armor was created.`
   },

   {
      position: 0,
      question: "What do the various 'Display Privacy' Advanced Options do?",
      answer: `These options control what information is visible in the Quick Crypt UI
      by default and when that information is automatically cleared.
      <p><b>Cache Time</b> is the number of
      seconds that <i>passwords</i> and <i>cleartext</i> are held in memory until
      automatically cleared. The default is 0, which immediately clears both values
      after encryption. Setting this to greater than 0 will store the last password
      and cleartext for that many seconds.
      This is useful when you want to encrypt or decrypt multiple items using the
      same password.</p><p><b>Clear When Hidden</b> automatically clears cached password
      and cleartext values when the browser tab displaying Quick Crypt is hidden,
      for example, when a screen lock occurs. Clear occurs even when there is
      "Cache Time" remaining.</p><p><b>Hide Passwords</b> obscures passwords as you type
      them. If you turn off this option, passwords are displayed in clear text when you
      enter them. You can switch password visibility on the fly regardless of this
      setting.</p>`
   },

];