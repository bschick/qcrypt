import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getRandom, bytesToBase64 } from '@qcrypt/crypto';
import {
   getUserCredPubKey,
   signUserCredProof,
   verifyUserCredProof,
   getRecoveryPubKey,
   signRecoveryProof,
   verifyRecoveryProof
} from './proof';

// Public keys derived from the fixed secret bytes 0..31, pinned to catch any
// derivation change or client/server divergence.
const USERCRED_VECTOR = 'KbUdM4TfRnUkOh7CZiY8ErCB5602BmHbaofWTqEWJ3Xn-c0hb2EgPgfViUq06nfeNSd9Nk073PlqCTATIgtpL_aYzJ_C_I89clDTYn4BTqMeJ-Ts7WDj4iflILZ6la1sivvSp1CM_yiTyKLl4BcGVUNiZWhYP_XujFfO5EfeeNpYkaCJMpLCSdbBghedoA_AEMaHqRnI92w2JUhrlR6ELcssJD_jxNLKMW5cOVhhlHu_6nG7UoiSqIN1K-a8zc1Ro8vx-jhoXEzNFHezBBSALtEIQT6qyzRJtyddYW0CF86-A2LzSpYY33QGVUgy9aWFgAUm0GEw9ACKHLwezGXu3dCeIAjriXfi2VB7N9MVmeCtV3RhyTgymeuau76fZsZWB0mb507Pclq1Nc8ii_ekTOtKJInndBSFHZmSImf7PQ11i8pc6DQnXYqEzLfObsub2zl9HizkSC9R_8i3kLvyqlrAuK95Vbrl9kprL_1UT16NvaA00aevXxq9Azor2wnxtZcXmLim6meqCs1sU240rynEdMVGm8NFtI8eiC41srqX2D1aaHbw4HQdi9AH4fa4mILiJhlXZ1VscuxSZsC0jSows28YS1BZLe0Bodt0bR2DHsXx3j0HY_9Xq-B-piTjK5HEmxL4XmrpXTXe16aUEnbICAf5SomaklammxjJCtfkVpQVF9ekHOVpm5TUfVJ0YlkgqpqNi3tbTE1SA8so0ykEkaENPlML4Bj_mhuvngQW5GAEv0IZdwDzOabNdvxpTTz9U5iofRcZD7uku0YGTQIZMutfby00dcLFm-io460DoT_BI8J68P43-yDpFwsSighCoD8K7LGhFT-yHvLjeQojjkpONMaMPTVRUpwk_IHAthtXv-MGAV-HvPmDOtFY8DoVM0IgviGWqENpMwcK4-JOG6trq0GRwgHFoJWAdhFJQySmNNoa2yBOPWvopt1cH9jTQxp4I-Z6np5E0C1LeS1-f3GhV0U4ckTWcCgkFzO9rqyk1oIp8UEVqiieT8XKAMH-svNulaHg5EtWTeQcNRrBV3B0N4aLS2W5VKDMHf-ZubUqAO3GObovHkiNC31BWYYLStHjvPkoHiY8ykIbD58-gHD9v46c7xCePHoyBaPtQtBsejXJRykbg1MAk3TzowjgFN_P8M99BDqvGB5ExaiKKbCK0Lot9Z3PC9KE2x-ZiCrjyD1cKgDBR28JcZiOOIEYUEzMfV1jCPO4UXDU1GxiublAl1aORZgI3i-1iHeJRa_1h6LDUYLHeGBhiYV6BOtvEKUQIRWCF-zPkshTh9tkv2_HWjNk5X_iBQKOyuQYh97T5DuHnfdJYbMIPL834EJ3p5Um-KfAQdGIlnR-FWu7PRRLuHzJxcNQbwmmgH2c8524aA7GOhPW_9EJqcFMHacxrh8m9EGcImo_PmPkPc0KpglMMOatv3jLSqHkSYdH-dDoEyqoAEMnIX2a5kFHhmJg8pnkFvknJDlrMuF9sSnnwO4Om9TRkUBsq4YP-KIhKZ_of5U1xFemajZoN8u7l52HgMha2iJS0gp5a_C7WKEL5mNmqfGVMrN7K_8MOqW57v-7zTWeE7kN9QyTH5wWv1M1AWrwOciLXHp0EGXvJGbh1jhg8XBy339A2aTp_enHhSWLOfSNB27JSuj7DrJGlNOOuzFUCtIR2il50JOVHODfZFOdgi7kHTYQ6GCYgDSA28PnG9YaDKTz2G9rXzOax6iSiMmSJAaugUohW5l26GilSw-Ynwk045Iad78VrCY6o-dLDZ74SNKCo4x61gPN0RNZ0ph93IrhRLSF5XDPAcNDs8zWkH48L40nbB-1K_KL4cD8V1fGv0LtMZT9vPRCwQvJcOEXfXC5rw3plbRmpyoccBSgiToVuqKMhnK8osuh61rNq6xOBCkgvXrPE9IjUuy0q9UN0aphzAZbvGzC9UiavWTwobEtVq1iPArx9If2_23s4v35db3XUZ7-1-tVd4ZKVOvyQ3hkP6lWaeYPRlPEmKTD2z5uA12MD3pZVkjTX9ZoMniDkXbt_Kld7OpXTgzv-2_tkYrAAglsnd6DKaJJn4IjuLXqs95a0qMeatJ9OJMoMuzAcWkgiBrq_hBGzKljNfqd5WOJhwSQ37Rku602jCTVBXbi9o1ED1AhiERNZfv0crifTOFvQLa-fpkJ9VNrSnMieIBEtMXSivZ6V39LebV8usXRMFjGJeYN0WfX78LZiUWBj_wO28cfk6hwZZIKZv9JLa8f-abep3vwJfTz_PYz2UbxPfcXN9tfVB4RGUFwFA_t3jUVXsy5hhg7ybvDggkqG6wWSBx3KbKEkXS7R00-v-oYn15QCwI5LXkNswgzIUrWLbOlJ186Rc0emLJOACOlp-C0lK0N_egeJLoGpippbHu6DAbHfzbn9p5CoyZz028Sg8xdY5yzcKh5gnlLkisxOqsY9Qke2ZhIFqNn54CaSmF4GtZwyG5PuEQ5xhSklWsnE_LHMV_U-s5sYXLF9i_TfkupVDp5LBEv8sxdLaqE4Jr-I1rloRfKwB5-2grJbCJHKrWU7L_GXTYoVa8xAxO-e_o9qMcgyl606KRKhFRn4dRLvuTZQwMjAFc';
const RECOVERY_VECTOR = 'epPlekwHIumHgX68k_MxOL6n4ERzBf-UJa6VWZuvP6EBc_velAotOBUA_rv1fnJRiR3h_i1UNqA-6H-oWOezQM2gLp6OUFaoejaIPAMDCwuVnR7tpBbnFlVrQd_xo24po0aD3_5O3IduJKgG3j7DO17hOMqLO2-hUZLeYnzWSxP51FN-bAvmufe-OTM3kovodpEHZr0rCSdvgGXrw_hAWJXmW8jP0B-dN7V7q5BwtplLhcehEehypZunnOkvI9sRnpa08embBJEGKOH9KySjGjZDOhPSCOmGpRrqRqzsf0SDeavlqkdRHr-q4ATdgoJAA-RF9jvPvzyfu8p5mok7UpC-TGPagO_HKOfARO4fsBXlFaIxLR-8FNYkXCjyUuFXfZskbpb4QJu9NggPLI4I6_7LJqa3RRohWfPsxDi3cdn8ISbvjUJJwoBAO8Bn1EANRiJGGInDQ3vLZmgXxvCpxOXXWZEFBR15vUvKPOHPAGSdFKo_uucXcRiHC0kNSbPpGrxNUJz_EiFuMLSGxPHRKSJmBusM9Mt9zZ_6F6Aw0D5Eb_Rx_Ss_2cR6AuOkP5WW8Zc5X1Sbo4K1GSF9vLbdEyr0vIK0rtEuHAvKhdy7ouOIcvJPiM4O0rk9AtQKpZ-6axNXumkICCoIZbb-Ewp1twxcHRfFhWx9Z4Gxx-vpz7yJkBpCvxcnkV5sLz0WQl1zOQpO48DjxJPiBXGUGVZHbRogaG2RpA48fmWcOmN4Dn_E2JqqOtnuZKmro-yF-Q5UZPv0QE7ceYnBDSSDAe7vM9L46TqeYEyLgAxs8LqmmRg4yULK0DYvYr8LzWFAK5R1wA9ADtLDSpUPSorPfAuwQfLomfKk-OWyn758vSJB-az1Eh4Z7DLTlti1nBlpWG4cef_mWW7DCgaEUY6Mtj_f6vL15pZESnFYBKtG9iS1xAMiI1iwIlVyQDANuppLZ0B2i-axrLbidZchnNBL-LH6Y_VLtcAfD-Jy6m1kCuAuwUc74kmwGiTTJVScN-t_Rh0x9V0Rn4qmKzelpZaEqBtA5TfuTY07l-7lnGvekn620CMi9LecXX98wKhUM3z8ZzKuzqfqcmLCSzLqMGP86SLam2zzZcHdOCEL_fYL714rTUVYm5imSDBRYIWKjaDowkRIkSshtjHpTAHhU2MjKiV19tS8CCBSptFDsSHZHiOT4heNpW2PbqmNd2YbNGxdJAALNZxSypH7_-4JjTl2qE1rnpMxG4xtjGRt8DqTpCsbJBFigLxNvY_tVXyfJEMNXd1z5dkUNuvRRGGkHHBCWkB6vv-wa8net06ZFmunSdjA354Yp2kVkl8b0SYbI0plJsoxqBxTmyU5qm5Ivo4cRIl9wrmL5k6OF8V6WsV1dhxep8WCvjixza1XnDGBhjr6BCdlQpcxYI4-iiafhvurtlv3LsknSXfNElnxl-9alt3evG6DgoQzY3jLwushxQElisU-pHqn_yUBU59LPF8QCXxWsgQYeoburArllhB9Th10TWZSJAN0dO1-H67LNzk1f0WZF61kRo6c7VJgOT9wa_k84Cp3vNQ8Tv3xIepJpCA6-owOa5CyfxicxZUc3N988FZ3ChcCR5dwYdORantVjTIsFwfcl1jODHfGNlaAD4YnmFOLPir63w9f3Umb59gYxT1segZEDcRYe9WOKNUdKILwYdfbjnauOhIgiyN3CSThbcNPYebJIXWIoyL_bsk_2e6mZy8Q_RM8yOQP9ReXiCKmUYqxlzxpdG_ba040hDn_OAkzCAkK_W0wYSbRbCNsNy-YQ-hS2jO5cx1Pdz8MK9yw3LF1OEZbEiLZ9LLV9zwv3sk1tOK-cWNQa6uaYDdIaDxSxAu1A8-IkZYwJzbTh7ovAeT_egfnyqInZVxjxcLnBs_h6hXZVLxVlKMukjS1Flr0vdkbcmcJGRx07NnWiIo8jmb7OevBpXwBo8cpUv-QU_wq7eNddvfJI-xUZw9Svv4HTXRcXix6jsubKF_tz_r9uidEt9c08ebXm2Gv7WdaitaxDeQ8Fp1cYRpdd0hW6hn5ZRYsEmYAKKsBM-Rsen4xuhryHG4fCY98J45uCpM0SgM741ra99bhHqCiF7mvba0NaZzRvfW5R-LrbqeY08HY85h5mw4-P1uej64T7TQh5p8YenoBd7t0IRQKX_95ykc0xJtzcmfIyTA0JKduFH0gwQN0OIx8ZCuPtkFyb-a1_S8fu-NCYKe7qlHyQZXm9EeiNvi4MwyMIKjK9Yow-ngNyb_C-wXpbu3WUu3lBzyNXLuZED3r9ZQF_z74Xi6AX8vXYDANnza5OSAqH2yupYVavIhnBxQdXI8kgJ0mwKJFcfeEykUFDTUqqqQht68Xe7si_yomoKsP-Kp1Z39wbev4CaI9s81v6nftEjZE7_TtJq3tBkqCl2w6R3tToBad0sclmwK5wgGz_nrlx8xEBMdVYoQ6pckQmBBqjH-w18U8kU-QEXe1fxJf15JudkqWBIxD_bCPoDi32NFp713cIh9jhzKsh9IwJQxJg_3z5frn5oICWZb70U8MyY22yvEGLX9VDMI7-57nZvwCSlLwlPEN5fARawuZGyEZIbQ4aPr0-EA';

describe('userCred proof', () => {
   let userId: string;

   beforeEach(async () => {
      await cryptoReady();
      userId = bytesToBase64(getRandom(16));
   });

   it('sign request and verfiy with derived public key', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'GET', '/v1/user', '1730000000000', 'abc');
      expect(verifyUserCredProof(pubKey, userId, 'GET', '/v1/user', '1730000000000', 'abc', signature)).toBe(true);
   });

   it('derives the pinned public key for a fixed secret', () => {
      const secret = new Uint8Array(32);
      for (let pos = 0; pos < secret.length; pos++) {
         secret[pos] = pos;
      }
      // Client and server derive this independently; they must produce identical bytes.
      expect(bytesToBase64(getUserCredPubKey(secret))).toBe(USERCRED_VECTOR);
   });

   it('throw when signed fields differs', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'POST', '/v1/passkeys', '100', 'aa');
      const otherUserId = bytesToBase64(getRandom(16));
      expect(() => verifyUserCredProof(pubKey, otherUserId, 'POST', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'DELETE', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/other', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/passkeys', '101', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/passkeys', '100', 'bb', signature)).toThrow();
   });

   it('throw when a the wrong public key is used', () => {
      const signature = signUserCredProof(getRandom(32), userId, 'GET', '/v1/user', '100', 'aa');
      const otherPubKey = getUserCredPubKey(getRandom(32));
      expect(() => verifyUserCredProof(otherPubKey, userId, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });

   it('thow when the signature is manipulated', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'GET', '/v1/user', '100', 'aa');
      signature[0] ^= 0x01;
      expect(() => verifyUserCredProof(pubKey, userId, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });
});

describe('recovery proof', () => {
   let userId: string;
   let challenge: string;

   beforeEach(async () => {
      await cryptoReady();
      userId = bytesToBase64(getRandom(16));
      challenge = bytesToBase64(getRandom(32));
   });

   it('sign challenge and verify with derived public key', () => {
      const secret = getRandom(32);
      const pubKey = getRecoveryPubKey(secret);
      const signature = signRecoveryProof(secret, userId, challenge);
      expect(verifyRecoveryProof(pubKey, userId, challenge, signature)).toBe(true);
   });

   it('derives the pinned public key for a fixed secret', () => {
      const secret = new Uint8Array(32);
      for (let pos = 0; pos < secret.length; pos++) {
         secret[pos] = pos;
      }
      // Client and server derive this independently; they must produce identical bytes.
      expect(bytesToBase64(getRecoveryPubKey(secret))).toBe(RECOVERY_VECTOR);
   });

   it('throw when signed fields differ', () => {
      const secret = getRandom(32);
      const pubKey = getRecoveryPubKey(secret);
      const signature = signRecoveryProof(secret, userId, challenge);
      const otherUserId = bytesToBase64(getRandom(16));
      const otherChallenge = bytesToBase64(getRandom(32));
      expect(() => verifyRecoveryProof(pubKey, otherUserId, challenge, signature)).toThrow();
      expect(() => verifyRecoveryProof(pubKey, userId, otherChallenge, signature)).toThrow();
   });

   it('throw when the wrong public key is used', () => {
      const signature = signRecoveryProof(getRandom(32), userId, challenge);
      const otherPubKey = getRecoveryPubKey(getRandom(32));
      expect(() => verifyRecoveryProof(otherPubKey, userId, challenge, signature)).toThrow();
   });

   it('throw when the signature is manipulated', () => {
      const secret = getRandom(32);
      const pubKey = getRecoveryPubKey(secret);
      const signature = signRecoveryProof(secret, userId, challenge);
      signature[0] ^= 0x01;
      expect(() => verifyRecoveryProof(pubKey, userId, challenge, signature)).toThrow();
   });

   it('does not collide with the userCred proof for the same secret', () => {
      const secret = getRandom(32);
      const recoveryPubKey = bytesToBase64(getRecoveryPubKey(secret));
      const userCredPubKey = bytesToBase64(getUserCredPubKey(secret));
      expect(recoveryPubKey).not.toBe(userCredPubKey);
   });
});
