//TODO: Fix packets with vectors

use std::{
    io::{Cursor, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    thread, vec,
};

use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use openssl::{pkey::Private, rsa::Rsa};
use packets::Handshake;

use crate::{
    packets::{read_i64, read_string, write_string, EncryptionRequest},
    server_list::{Player, ServerList, Version},
};

mod packets;
mod server_list;

const PROTOCOL: i32 = 757;

fn handle_client(mut stream: TcpStream, rsa: Rsa<Private>) {
    let packet_size: i32 = stream.read_var_int().unwrap().into();
    let packet_id: i32 = stream.read_var_int().unwrap().into();

    let mut data = vec![0; packet_size as usize];
    stream.read(&mut data).unwrap();

    let mut cursor = Cursor::new(data);

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

            stream.write(res.as_slice()).unwrap();

            stream.flush().unwrap();

            let packet_size: i32 = stream.read_var_int().unwrap().into();
            let packet_id: i32 = stream.read_var_int().unwrap().into();
            
            println!("{}", packet_size);

            let mut data = vec![0; packet_size as usize];
            if let Ok(_) = stream.read(&mut data) {
                let mut cursor = Cursor::new(data);
                if packet_id == 0x01 {
                    println!("Got ping");
                    let numb = read_i64(&mut cursor);

                    let mut cursor = Cursor::new(Vec::with_capacity(10));
                    cursor.write_var_int(VarInt::from(packet_size)).unwrap();
                    cursor.write_var_int(VarInt::from(packet_id)).unwrap();

                    let mut res = Vec::new();

                    res.append(cursor.get_mut());
                    res.append(&mut numb.to_le_bytes().to_vec());

                    stream.write(res.as_slice()).unwrap();
                }
            }
        }

        if handshake.next_state == 2 {
            println!("Login stage");
            let packet_size: i32 = stream.read_var_int().unwrap().into();
            let packet_id: i32 = stream.read_var_int().unwrap().into();
            
            let mut data = vec![0; packet_size as usize];
            stream.read(&mut data).unwrap();
            println!("Read");
            let mut cursor = Cursor::new(data);

            if packet_id == 0x00 {
                let user = read_string(&mut cursor);

                println!("Received connection request from: {}", user);
                println!("Sending encryption request...");

                let request = EncryptionRequest::new(rsa);

                stream.write(request.encode().as_slice()).unwrap();

                let packet_size: i32 = stream.read_var_int().unwrap().into();
                let packet_id: i32 = stream.read_var_int().unwrap().into();
            
                let mut data = vec![0; packet_size as usize];
                if let Ok(_) = stream.read(&mut data) {
                    let mut cursor = Cursor::new(data);

                    if packet_id == 0x01 {
                        println!("Got encrypt response");
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
