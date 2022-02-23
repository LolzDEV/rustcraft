
use std::{
    io::{Cursor, Read, Write, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    thread, vec,
};


use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use num_bigint::BigInt;
use packets::Handshake;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{ToPublicKey}};
use sha1::{Sha1, Digest};
use uuid::Uuid;

use crate::{
    packets::{read_i64, read_string, write_string, EncryptionRequest, EncryptionResponse, LoginSuccess},
    server_list::{Player, ServerList, Version}, login::AuthRespone,
};

mod packets;
mod server_list;
mod login;
mod play;

const PROTOCOL: i32 = 757;

fn handle_client(stream: TcpStream, public_key: RsaPublicKey, private_key: RsaPrivateKey) {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    let packet_size: i32 = reader.read_var_int().unwrap().into();

    let mut data = vec![0; packet_size as usize];
    reader.read(&mut data).unwrap();

    let mut cursor = Cursor::new(data);

    let packet_id: i32 = cursor.read_var_int().unwrap().into();

    let handshake;

    if packet_id == 0 {
        println!("Handshaking...");
        handshake = Handshake::from_data(&mut cursor);

        if handshake.next_state == 1 {
            println!("Requested Status");
            let list = serde_json::to_string(&ServerList {
                version: Version {
                    name: "1.18.1".to_string(),
                    protocol: PROTOCOL,
                },
                players: server_list::Players {
                    max: 20,
                    online: 1,
                    sample: vec![Player {
                        name: "LolzDEV".to_string(),
                        id: "82c47a21-4cbe-4eee-a729-53a3b89ec6ee".to_string(),
                    }],
                },
                description: server_list::Description {
                    text: "Test server written in rust".to_string(),
                },
                favicon: "".to_string(),
            })
            .unwrap();

            let mut res = Vec::new();

            let mut cur = Cursor::new(Vec::with_capacity(5));

            cur.write_var_int(VarInt::from((write_string(list.clone()).len() + 1) as i32))
                .unwrap();

            cur.write_var_int(VarInt::from(0x00)).unwrap();

            res.append(&mut cur.get_mut().to_vec());

            res.append(&mut write_string(list));

            writer.write(res.as_slice()).unwrap();

            writer.flush().unwrap();


            reader.read_var_int().unwrap();
            reader.read_var_int().unwrap();
            let packet_size: i32 = reader.read_var_int().unwrap().into();
    
            let mut data = vec![0; packet_size as usize];
            if let Ok(_) = reader.read(&mut data) {
                println!("{}", data.len());
                let mut cursor = Cursor::new(data);
                let packet_id: i32 = cursor.read_var_int().unwrap().into();

                println!("{}", packet_id);
                if packet_id == 0x01 {
                    let numb = read_i64(&mut cursor);

                    let mut cursor = Cursor::new(Vec::with_capacity(10));
                    cursor.write_var_int(VarInt::from(packet_size)).unwrap();
                    cursor.write_var_int(VarInt::from(packet_id)).unwrap();

                    let mut res = Vec::new();

                    res.append(cursor.get_mut());
                    res.append(&mut numb.to_le_bytes().to_vec());

                    writer.write(res.as_slice()).unwrap();
                    writer.flush().unwrap();
                }
            }
        }

        if handshake.next_state == 2 {
            println!("Login stage");
            let packet_size: i32 = reader.read_var_int().unwrap().into();
            
            let mut data = vec![0; packet_size as usize];
            reader.read(&mut data).unwrap();
            let mut cursor = Cursor::new(data);
            let packet_id: i32 = cursor.read_var_int().unwrap().into();

            if packet_id == 0x00 {
                let user = read_string(&mut cursor);

                println!("Received connection request from: {}", user);
                println!("Sending encryption request...");

                let (request, token) = EncryptionRequest::new(public_key.clone());

                writer.write(request.clone().encode().as_slice()).unwrap();

                writer.flush().unwrap();

                let packet_size: i32 = reader.read_var_int().unwrap().into();

                println!("{}", packet_size);
            
                let mut data = vec![0; packet_size as usize];
                if let Ok(_) = reader.read(&mut data) {
                    let mut cursor = Cursor::new(data);
                    let packet_id: i32 = cursor.read_var_int().unwrap().into();

                    if packet_id == 0x01 {
                        println!("Got encrypt response");

                        let response = EncryptionResponse::new(&mut cursor);

                        let decr = private_key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &response.token).unwrap();
                        

                        if decr != token {
                            println!("Login failed!");
                        }

                        let shared_secret = private_key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &response.secret).unwrap();

                        let mut hash = Sha1::new();
                        hash.update(request.id.as_slice().to_ascii_lowercase());
                        hash.update(shared_secret);
                        hash.update(public_key.to_public_key_der().unwrap().as_ref());

                        let hex = BigInt::from_signed_bytes_be(hash.finalize().as_slice()).to_str_radix(16);

                        let mut res = reqwest::blocking::get(&format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={user}&serverId={hex}")).unwrap();
                    
                        let mut cont = String::new();
                        res.read_to_string(&mut cont).unwrap();

                        let auth_response: AuthRespone = serde_json::from_str(&cont).unwrap();

                        let uuid = Uuid::parse_str(&auth_response.id).unwrap();

                        let success = LoginSuccess::new(uuid, user);

                        writer.write(success.encode().as_slice()).unwrap();
                        writer.flush().unwrap();
                    }
                }
            }
        }
        
    }

    /*
    while match stream.read(&mut data) {
        Ok(_size) => {
            let mut cursor = Cursor::new(data);
            let _packet_size: i32 = cursor.read_var_int().unwrap().into();
            let packet_id: i32 = cursor.read_var_int().unwrap().into();

            match packet_id {
                0 => {}
                _ => (),
            }

            true
        }
        Err(_) => {
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
    */
}

fn main() {
    println!("Generating RSA key...");
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);

    let listener = TcpListener::bind("0.0.0.0:25565").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let public = pub_key.clone();
                let private = priv_key.clone();
                thread::spawn(move || {
                    handle_client(stream, public, private);
                });
            }
            Err(e) => eprintln!("Failed to connect, {}", e),
        }
    }
}
