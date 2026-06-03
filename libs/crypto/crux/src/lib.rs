use wasm_bindgen::prelude::*;
use libcrux_ml_dsa::ml_dsa_65;

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
