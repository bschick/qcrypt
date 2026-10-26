use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{compiler_fence, Ordering};
use wasm_bindgen::prelude::*;
use libcrux_ml_dsa::ml_dsa_65;

// wasm memory outlives each call, so a freed block keeps its contents readable from JS until a later
// allocation overwrites it. This allocator zeroes every block it frees, which covers keys copied into
// Vecs, the input copies that wasm-bindgen frees, and anything libcrux allocates.
struct ZeroOnFree;

// The trait's default realloc allocates, copies, and calls dealloc, so blocks moved by realloc are zeroed too
unsafe impl GlobalAlloc for ZeroOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        for i in 0..layout.size() {
            ptr.add(i).write_volatile(0);
        }
        compiler_fence(Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: ZeroOnFree = ZeroOnFree;

// Defined by wasm-ld
extern "C" {
    static __stack_low: u8;
    static __stack_high: u8;
}

// Returns the [low, high) addresses of the shadow stack. libcrux leaves key material in its stack
// frames, and no frame is live between calls, so JS zeroes this whole range after each call.
#[wasm_bindgen]
pub fn stack_bounds() -> Vec<u32> {
    vec![
        core::ptr::addr_of!(__stack_low) as u32,
        core::ptr::addr_of!(__stack_high) as u32,
    ]
}

#[wasm_bindgen]
pub struct MlDsa65KeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl MlDsa65KeyPair {
    #[wasm_bindgen(getter)]
    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn sk(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

fn to32(bytes: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{what} must be 32 bytes")))
}

#[wasm_bindgen]
pub fn ml_dsa_65_keygen(seed: &[u8]) -> Result<MlDsa65KeyPair, JsError> {
    let pair = ml_dsa_65::generate_key_pair(to32(seed, "seed")?);
    Ok(MlDsa65KeyPair {
        pk: pair.verification_key.as_slice().to_vec(),
        sk: pair.signing_key.as_slice().to_vec(),
    })
}

#[wasm_bindgen]
pub fn ml_dsa_65_sign(
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8],
) -> Result<Vec<u8>, JsError> {
    let signing_key = ml_dsa_65::MLDSA65SigningKey::new(
        sk.try_into().map_err(|_| JsError::new("bad signing key length"))?,
    );
    let signature = ml_dsa_65::sign(&signing_key, message, context, to32(randomness, "randomness")?)
        .map_err(|_| JsError::new("sign failed"))?;
    Ok(signature.as_slice().to_vec())
}

#[wasm_bindgen]
pub fn ml_dsa_65_verify(
    pk: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    let verification_key = ml_dsa_65::MLDSA65VerificationKey::new(
        pk.try_into().map_err(|_| JsError::new("bad verification key length"))?,
    );
    let signature = ml_dsa_65::MLDSA65Signature::new(
        signature.try_into().map_err(|_| JsError::new("bad signature length"))?,
    );
    Ok(ml_dsa_65::verify(&verification_key, message, context, &signature).is_ok())
}
