/* MIT License

Copyright (c) 2025-2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */
export const FLOW_ANIM_MS = 420;

// Max path depth below top-level (limited because loops exists)
export const FLOW_MAX_DEPTH = 14;

export interface FlowItem {
   label: string;
   svg: string;
   search?: string;
}

export interface FlowOverview extends FlowItem {
   subsystems: string[];
}

// Top-level entry points shown in the initial grid view and as path[0] of the
// route query string. Keys are the route segment values.
export const FLOW_OVERVIEWS: Record<string, FlowOverview> = {
   encryption: {
      label: 'Encryption',
      svg: '/assets/flow/encryption.svg',
      search: 'cipher data',
      subsystems: ['01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e'],
   },
   decryption: {
      label: 'Decryption',
      svg: '/assets/flow/decryption.svg',
      search: 'message',
      subsystems: ['0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c'],
   },
};

// Subprocesses keyed by the 2-character lowercase hex value of the blue byte
// of Lucidchart placeholder fill #f4d9NN. The same key is also the SVG
// data-target attribute value and the URL path segment. 'ff' is reserved
export const FLOW_SUBSYSTEMS: Record<string, FlowItem> = {
   '01': { label: 'Sign Block0', svg: '/assets/flow/sign_cd0.svg' },
   '02': { label: 'Sign BlockN', svg: '/assets/flow/sign_cdN.svg' },
   '03': {
      label: 'Encrypt Block0',
      svg: '/assets/flow/encrypt_m0.svg',
      search: 'cipher key message symmetric km0 kc',
   },
   '04': { label: 'Pack Block0 AD', svg: '/assets/flow/pack_ad0.svg', search: 'additional data' },
   '05': { label: 'Derive Signing Key', svg: '/assets/flow/derive_enc_kS.svg' },
   '06': {
      label: 'Encryption Input',
      svg: '/assets/flow/obtain_enc_input.svg',
      search: 'm mN m0 niv salt ns le loop end user credential algorithm iteration random passkey',
   },
   '07': { label: 'Derive Block0 Key', svg: '/assets/flow/derive_enc_kM0.svg', search: 'password hint' },
   '08': { label: 'Encrypt Hint', svg: '/assets/flow/encrypt_h.svg', search: 'key symmetric nivh kh padding' },
   '09': { label: 'Derive Key Commit', svg: '/assets/flow/derive_enc_kC.svg' },
   '0a': { label: 'Derive Hint Nonce', svg: '/assets/flow/derive_enc_nIVH.svg' },
   '0b': { label: 'Derive Hint Key', svg: '/assets/flow/derive_enc_kH.svg' },
   '0c': { label: 'Pack BlockN AD', svg: '/assets/flow/pack_adN.svg', search: 'random niv additional data' },
   '0d': {
      label: 'Encrypt BlockN',
      svg: '/assets/flow/encrypt_mN.svg',
      search: 'cipher key message symmetric kmn kc',
   },
   '0e': { label: 'Derive BlockN Key', svg: '/assets/flow/derive_enc_kMN.svg' },
   '0f': {
      label: 'Decryption Input',
      svg: '/assets/flow/obtain_dec_input.svg',
      search: 'cd cdN cd0 user credential passkey',
   },
   '10': { label: 'Verify Block0', svg: '/assets/flow/verify_cd0.svg' },
   '11': { label: 'Verify BlockN', svg: '/assets/flow/verify_cdN.svg' },
   '12': { label: 'Unpack Block0 AD', svg: '/assets/flow/unpack_ad0.svg', search: 'additional data' },
   '13': { label: 'Derive Signing Key', svg: '/assets/flow/derive_dec_kS.svg' },
   '14': { label: 'Derive Hint Nonce', svg: '/assets/flow/derive_dec_nIVH.svg' },
   '15': { label: 'Derive Hint Key', svg: '/assets/flow/derive_dec_kH.svg' },
   '16': { label: 'Derive Block0 Key', svg: '/assets/flow/derive_dec_kM0.svg', search: 'password hint' },
   '17': { label: 'Decrypt Hint', svg: '/assets/flow/decrypt_hE.svg', search: 'key symmetric nivh kh padding' },
   '18': { label: 'Verify Key Commit', svg: '/assets/flow/verify_dec_kC.svg' },
   '19': {
      label: 'Decrypt Block0',
      svg: '/assets/flow/decrypt_mE0.svg',
      search: 'cipher key message symmetric km0 kc',
   },
   '1a': {
      label: 'Decrypt BlockN',
      svg: '/assets/flow/decrypt_mEN.svg',
      search: 'cipher key message symmetric kmn kc',
   },
   '1b': { label: 'Unpack BlockN AD', svg: '/assets/flow/unpack_adN.svg', search: 'additional data' },
   '1c': { label: 'Derive BlockN Key', svg: '/assets/flow/derive_dec_kMN.svg' },
};

// === GENERATED by `pnpm svgo:flow` — do not edit by hand ===
// SHA-256 (base64url) of each flow SVG asset. SvgInlineDirective rejects any
// fetched asset whose bytes do not match
export const FLOW_SVG_HASHES: Record<string, string> = {
   '/assets/flow/encryption.svg': 'sha256-W8JyVr789s2lR3iAcOZ-lll2iAbIxJHaSBsf7Li--_s',
   '/assets/flow/decryption.svg': 'sha256-JJmpo32mQRC3YsbaIfyNrqAFAIwbNkM7E7bFEnbAnzo',
   '/assets/flow/verify_cd0.svg': 'sha256-qFrPLijydOKpmh9ezRJfovwa6jan_pPYKNPBsZ83vaY',
   '/assets/flow/verify_cdN.svg': 'sha256-HC4amNv6NiirOTTqBDhydSMH1UwpgIFALgbz0EZIrvs',
   '/assets/flow/unpack_ad0.svg': 'sha256-QxWyyWEKdVUM3QM1OwItlV7Un4ty2_lDHJRr601M7ds',
   '/assets/flow/derive_dec_kS.svg': 'sha256-cwz-DDySj5LshV39k_VFi7nF0hR_PuJR_ONwr3FmOaA',
   '/assets/flow/derive_dec_nIVH.svg': 'sha256-SHwG0aVnCbLOtptTtIDad3-5t5ffJX1I_ocT-SS9RNQ',
   '/assets/flow/derive_dec_kH.svg': 'sha256-2uW6cLtFejZGiP-zPDGBeK9ySxGhuTXH4NY_EeY0hB0',
   '/assets/flow/derive_dec_kM0.svg': 'sha256-wBfOn8arsaIos3wHpHGKAYy2Zd-ae0hzxuxm8CKW_00',
   '/assets/flow/decrypt_hE.svg': 'sha256-QwhaGRhK1F1CdAmPrcw9E44slpMbCq5SbmA2Usn5c14',
   '/assets/flow/verify_dec_kC.svg': 'sha256-Swnl4frFt0ztTRHynY5TjgyR3ebIAG9SlL3YdCLQ9x4',
   '/assets/flow/decrypt_mE0.svg': 'sha256-ruD_Xu-ADLv0dHt923krPwxaTVCC9n2jR7HnJQQCDbU',
   '/assets/flow/sign_cd0.svg': 'sha256-z0e_KvzbVnXRTO8A8xtgyn29zao11AQFdCXPVYtVYGM',
   '/assets/flow/sign_cdN.svg': 'sha256-QpDzpio4_ckNv227Ic_PdNQlm0CMuFY2ENsuo2O9Na4',
   '/assets/flow/encrypt_m0.svg': 'sha256-8Qb-cdrjrBtdEN5x4VjWZjag0cJ233AdamLRpDkXsJw',
   '/assets/flow/pack_ad0.svg': 'sha256-FKUT7MdYYzxA4_68e5DkPCkw-l1dh-RSADwBFoO4swA',
   '/assets/flow/derive_enc_kS.svg': 'sha256-O0ucNMYAJqu415HaKjfOzeQuEwFe-kA2RoTCGmF-AAY',
   '/assets/flow/obtain_enc_input.svg': 'sha256-OvVl77bB1sh2f3x2iRg_obZpubLdKoc6B-WbQT_Kbr8',
   '/assets/flow/derive_enc_kM0.svg': 'sha256-jNJ5_6eJ3DXUN47tZFu1fITu_lW_iU5pZFiCex_iZHY',
   '/assets/flow/encrypt_h.svg': 'sha256-QEcoPHrcazYr7IMNBRm0YLVPgkijFVjBG7eu6K_Z1B0',
   '/assets/flow/derive_enc_kC.svg': 'sha256-GggnhtVbOlbNQSuJohSXmlMSBJwVFZNp_EiBF-1OMaA',
   '/assets/flow/derive_enc_nIVH.svg': 'sha256-iEEuvrjlssftGpgc4cRn_r-fKd2VzBsdVcxWJMNtfm8',
   '/assets/flow/derive_enc_kH.svg': 'sha256-Lnr0ABmFhsVavtlQRTR31ks_wUCTab2wU44lWXb2c4I',
   '/assets/flow/pack_adN.svg': 'sha256-0mInm26EQVP1KnKydAsKM4BGAQOcPorp5Lp-3pxyTPw',
   '/assets/flow/encrypt_mN.svg': 'sha256-errdHjolV-7aL1N3bshXeMvMhhy7LRKlRP2ltif5LIk',
   '/assets/flow/derive_enc_kMN.svg': 'sha256-9jhN-KDaEIaz2Sniz0oUvGz55JAeY5cKM7srbENLWiE',
   '/assets/flow/obtain_dec_input.svg': 'sha256-iuFoP-qvawaZJUlpSfcSvgM0d9mOyu311gd6HeIzqmU',
   '/assets/flow/decrypt_mEN.svg': 'sha256-EJQfFsU1QMwMHC9DTa2bb23sAqNqfOeLktnDWAxsbKs',
   '/assets/flow/unpack_adN.svg': 'sha256-esxigSVcKpYzJ3XmZoP_8Ajmj5oXJ3yxy5bJrEKmk_s',
   '/assets/flow/derive_dec_kMN.svg': 'sha256-wT48enE7j9kTwPThJhur9pa_yb-ugihAwW3OfoppVRc',
};
// === END GENERATED ===
