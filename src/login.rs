use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRespone {
    pub id: String,
    pub name: String,
    pub properties: Vec<AuthProperty>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthProperty {
    pub name: String,
    pub value: String,
    pub signature: String
}