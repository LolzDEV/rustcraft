//TODO: Fix packets with vectors

use std::{
    io::{Cursor, Read, Write, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    thread, vec,
};

use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use openssl::{pkey::Private, rsa::{Rsa, Padding}};
use packets::Handshake;

use crate::{
    packets::{read_i64, read_string, write_string, EncryptionRequest, EncryptionResponse},
    server_list::{Player, ServerList, Version},
};

mod packets;
mod server_list;

const PROTOCOL: i32 = 757;

fn handle_client(mut stream: TcpStream, rsa: Rsa<Private>) {
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


            let packet_size: i32 = reader.read_var_int().unwrap().into();
            let packet_size: i32 = reader.read_var_int().unwrap().into();
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

                let (request, token) = EncryptionRequest::new(rsa.clone());

                writer.write(request.encode().as_slice()).unwrap();

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

                        let mut decr = vec![0u8; response.token_length as usize];

                        println!("Encrypted token: {:?}", response.token);

                        rsa.public_decrypt(response.token.as_slice(), &mut decr, Padding::PKCS1).unwrap();
                        println!("Decrypted token: {:?}", decr);
                        
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
    let rsa = Rsa::generate(1024).unwrap();

    let listener = TcpListener::bind("0.0.0.0:25565").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rsa = rsa.clone();
                thread::spawn(move || {
                    handle_client(stream, rsa);
                });
            }
            Err(e) => eprintln!("Failed to connect, {}", e),
        }
    }
}
