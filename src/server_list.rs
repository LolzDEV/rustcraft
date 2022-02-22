use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Version {
    pub name: String,
    pub protocol: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Player {
    pub name: String,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Players {
    pub max: i32,
    pub online: i32,
    pub sample: Vec<Player>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Description {
    pub text: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerList {
    pub version: Version,
    pub players: Players,
    pub description: Description,
    pub favicon: String,
}
