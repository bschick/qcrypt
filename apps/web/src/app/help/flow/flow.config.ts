export const FLOW_ANIM_MS = 420;

// Max path depth (top-level overview + subprocess descendants combined).
export const FLOW_MAX_DEPTH = 10;

export interface FlowItem {
   label: string;
   svg: string;
}

// Top-level entry points shown in the initial grid view and as path[0] of the
// route query string. Keys are the route segment values.
export const FLOW_OVERVIEWS: Record<string, FlowItem> = {
   'encryption': { label: 'Encryption', svg: '/assets/flow/v7/encryption.svg' },
   'decryption': { label: 'Decryption', svg: '/assets/flow/v7/decryption.svg' },
};

// Subprocesses keyed by the 2-character lowercase hex value of the blue byte
// of Lucidchart placeholder fill #f4d9NN. The same key is also the SVG
// data-target attribute value and the URL path segment. 'ff' is reserved
// (canonical fill, indicates an already-tagged element).
export const FLOW_SUBSYSTEMS: Record<string, FlowItem> = {
   '01': { label: 'Sign Block 0',         svg: '/assets/flow/v7/sign_cd0.svg' },
   '02': { label: 'Sign Block N',         svg: '/assets/flow/v7/sign_cdN.svg' },
   '03': { label: 'Encrypt Block 0',      svg: '/assets/flow/v7/encrypt_m0.svg' },
   '04': { label: 'Pack Block 0 AD',      svg: '/assets/flow/v7/pack_ad0.svg' },
   '05': { label: 'Derive Signing Key',   svg: '/assets/flow/v7/derive_enc_kS.svg' },
   '06': { label: 'Obtain Input',         svg: '/assets/flow/v7/obtain_enc_input.svg' },
   '07': { label: 'Derive Block 0 Key',   svg: '/assets/flow/v7/derive_enc_kM0.svg' },
   '08': { label: 'Encrypt Hint',         svg: '/assets/flow/v7/encrypt_h.svg' },
   '09': { label: 'Derive Commit Key',    svg: '/assets/flow/v7/derive_enc_kC.svg' },
   '0a': { label: 'Derive Hint Nonce',    svg: '/assets/flow/v7/derive_enc_nIVH.svg' },
   '0b': { label: 'Derive Hint Key',      svg: '/assets/flow/v7/derive_enc_kH.svg' },
   '0c': { label: 'Pack Block N AD',      svg: '/assets/flow/v7/pack_adN.svg' },
   '0d': { label: 'Encrypt Block N',      svg: '/assets/flow/v7/encrypt_mN.svg' },
   '0e': { label: 'Derive Block N Key',   svg: '/assets/flow/v7/derive_enc_kMN.svg' },
   '0f': { label: 'Obtain Input',         svg: '/assets/flow/v7/obtain_dec_input.svg' },
   '10': { label: 'Verify Block 0',       svg: '/assets/flow/v7/verify_cd0.svg' },
   '11': { label: 'Verify Block N',       svg: '/assets/flow/v7/verify_cdN.svg' },
   '12': { label: 'Unpack Block 0 AD',    svg: '/assets/flow/v7/unpack_ad0.svg' },
   '13': { label: 'Derive Signing Key',   svg: '/assets/flow/v7/derive_dec_kS.svg' },
   '14': { label: 'Derive Hint Nonce',    svg: '/assets/flow/v7/derive_dec_nIVH.svg' },
   '15': { label: 'Derive Hint Key',      svg: '/assets/flow/v7/derive_dec_kH.svg' },
   '16': { label: 'Derive Block 0 Key',   svg: '/assets/flow/v7/derive_dec_kM0.svg' },
   '17': { label: 'Decrypt Hint',         svg: '/assets/flow/v7/decrypt_hE.svg' },
   '18': { label: 'Derive Commit Key',    svg: '/assets/flow/v7/derive_dec_kC.svg' },
   '19': { label: 'Decrypt Block 0',      svg: '/assets/flow/v7/decrypt_mE0.svg' },
   '1a': { label: 'Decrypt Block N',      svg: '/assets/flow/v7/decrypt_mEN.svg' },
   '1b': { label: 'Unpack Block N AD',    svg: '/assets/flow/v7/unpack_adN.svg' },
   '1c': { label: 'Derive Block N Key',   svg: '/assets/flow/v7/derive_dec_kMN.svg' },
};
