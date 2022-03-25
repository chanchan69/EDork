use rsa::{RsaPublicKey, pkcs1::FromRsaPublicKey, PaddingScheme, PublicKey};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::io::{self, Write, Read};
use std::path::PathBuf;
use std::env;
use rand::Rng;
use rsa::pkcs8::FromPublicKey;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJXpzc4fUzuD9wsCjOIX
erl+pH7ZTDJEh3cNxF9bMSetH8738LuYoJXd2TuxcZ/0/fE7JwxOCfayEUbjTwX7
eLqRmRLTKlXaHb19DFeXhYjEtB1MT5URJnQFs6iWA59+0AsR/LPdmEdM4CM358UX
l2jptEgS3ClkYyZSo1SQNEkwtQ10jmwrVuWrff6hl4taok43d/bMdr/qUrYLNDZn
bN4uaFw0PSJBJKZy79laGZrq96iBbqDzrOvuEfLzpML+15ctomTMqD7yMOkknANV
13DRIhCUcaRRiRN9TE4hEpTKNGc08BEKxR21hagHUD153mBNgKB1XQhzwJtrx00n
ZwIDAQAB
-----END PUBLIC KEY-----";

fn encrypt_payload(data: &[u8]) -> Vec<u8> {
    let aes_key = rand::thread_rng().gen::<[u8; 16]>();
    let aes_iv = rand::thread_rng().gen::<[u8; 16]>();

    let aes_cipher = Aes128Cbc::new_from_slices(aes_key.as_slice(), aes_iv.as_slice()).unwrap();

    let mut buf = data.to_vec();
    let cipher_text = aes_cipher.encrypt(&mut buf, data.len() - 16).unwrap();

    let rsa_key = RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY).unwrap();
    let enc_key = rsa_key.encrypt(&mut rand::thread_rng(), PaddingScheme::new_pkcs1v15_encrypt(), aes_key.as_slice()).unwrap();

    let mut final_data: Vec<u8> = vec![];

    final_data.append(&mut enc_key.to_vec());
    final_data.append(&mut aes_iv.to_vec());
    final_data.append(&mut cipher_text.to_vec());

    final_data
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let path = match args.get(1) {
        Some(path) => path,
        None => { println!("please pass the path to your input file as positional argument 1"); return;}
    };

    let content = read_to_string(path.into()); // read the content to a string (lossy) so that there are no encoding errors when decrypting the edork file
    let raw = content.as_bytes();

    let final_data = encrypt_payload(raw);

    std::fs::write(path.replace(".txt", ".edork"), final_data);
}

fn read_to_string(path: PathBuf) -> String {
    let mut buf: Vec<u8> = vec![];
    std::fs::File::open(path).unwrap().read_to_end(&mut buf);
    String::from_utf8_lossy (&buf).to_string()
}
