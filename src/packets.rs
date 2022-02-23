use std::io::{Cursor, Write};

use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use openssl::{pkey::Private, rsa::Rsa};

pub fn read_string(cursor: &mut Cursor<Vec<u8>>) -> String {
    let lenght: i32 = cursor.read_var_int().unwrap().into();
    let pos = cursor.position();

    let mut value = Vec::new();

    while cursor.position() < pos + lenght as u64 {
        value.push(cursor.get_ref()[cursor.position() as usize]);
        cursor.set_position(cursor.position() + 1);
    }

    String::from_utf8(value).unwrap()
}

pub fn read_u16(cursor: &mut Cursor<Vec<u8>>) -> u16 {
    let number = ((cursor.get_ref()[(cursor.position() + 0) as usize] as u16) << 8)
        | cursor.get_ref()[(cursor.position() + 1) as usize] as u16;

    cursor.set_position(cursor.position() + 2);

    number
}

pub fn read_i64(cursor: &mut Cursor<Vec<u8>>) -> i64 {
    let mut bytes: [u8; 8] = [0u8; 8];
    bytes.copy_from_slice(
        &cursor.get_ref()[cursor.position() as usize..(cursor.position() + 8) as usize],
    );

    let number = i64::from_le_bytes(bytes);

    cursor.set_position(cursor.position() + 8);

    number
}

pub fn read_bytes(cursor: &mut Cursor<Vec<u8>>, len: usize) -> Vec<u8> {
    let res = cursor.get_ref().as_slice()[cursor.position() as usize..cursor.position() as usize +len].to_vec();
    cursor.set_position(cursor.position() + len as u64);

    res
}

pub fn write_string(data: String) -> Vec<u8> {
    let mut cur = Cursor::new(Vec::with_capacity(5));

    cur.write_var_int(VarInt::from(data.len() as i32)).unwrap();

    let mut res = Vec::new();

    res.append(cur.get_mut());

    res.append(&mut data.as_bytes().to_vec());

    res
}

pub struct Handshake {
    pub protocol: i32,
    pub address: String,
    pub port: u16,
    pub next_state: i32,
}

impl Handshake {
    pub fn from_data(cursor: &mut Cursor<Vec<u8>>) -> Self {
        let protocol: i32 = cursor.read_var_int().unwrap().into();

        let addr = read_string(cursor);

        let port = read_u16(cursor);

        let next: i32 = cursor.read_var_int().unwrap().into();

        Self {
            protocol,
            address: addr,
            port,
            next_state: next,
        }
    }
}

pub struct EncryptionRequest {
    pub id: Vec<u8>,
    pub key_length: i32,
    pub key: Vec<u8>,
    pub token_length: i32,
    pub token: Vec<u8>,
}

impl EncryptionRequest {
    pub fn new(key: Rsa<Private>) -> (Self, Vec<u8>) {
        let key = key.public_key_to_der().unwrap();
        let id = write_string(String::from_utf8(vec![0, 0, 0, 0, 0]).unwrap());
        let key_length = key.len() as i32;
        let token_length = 4;
        let token: Vec<u8> = (0..4).map(|_| rand::random::<u8>()).collect();

        (Self {
            id,
            key_length,
            key,
            token: token.clone(),
            token_length
        }, token)
    }

    pub fn encode(self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::with_capacity(10));

        cursor.write_var_int(VarInt::from(0x01)).unwrap();
        cursor.write(self.id.as_slice()).unwrap();
        cursor.write_var_int(VarInt::from(self.key_length)).unwrap();
        cursor.write(self.key.as_slice()).unwrap();
        cursor.write_var_int(VarInt::from(self.token_length)).unwrap();
        cursor.write(self.token.as_slice()).unwrap();

        let size = cursor.get_ref().to_vec().len();

        let mut result = Vec::new();
        result.write_var_int(VarInt::from(size as i32)).unwrap();
        result.append(cursor.get_mut());

        result
    }
}

pub struct EncryptionResponse {
    pub secret_length: i32,
    pub secret: Vec<u8>,
    pub token_length: i32,
    pub token: Vec<u8>
}

impl EncryptionResponse {
    pub fn new(cursor: &mut Cursor<Vec<u8>>) -> Self {
        let secret_length: i32 = cursor.read_var_int().unwrap().into();
        let secret = read_bytes(cursor, secret_length as usize);
        let token_length: i32 = cursor.read_var_int().unwrap().into();
        let token = read_bytes(cursor, token_length as usize);

        Self {
            secret_length,
            secret,
            token_length,
            token
        }
    }
}