mod vrchat;

use std::fs::File;
use std::io::{Read, Write};
use std::sync::Mutex;

use rayon::prelude::*;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use tfhe::{prelude::*, ClientKey, CompressedFheUint128, FheBool, FheUint128, ServerKey};
use tfhe::{generate_keys, set_server_key, ConfigBuilder};
use tokio::fs;
use vrchatapi::apis::authentication_api::{get_current_user, verify2_fa};
use vrchatapi::apis::configuration::Configuration;
use vrchatapi::models::TwoFactorAuthCode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("共通フレンド検索ツール\n");

    let mut mode = String::new();
    print!("モードを選択してください(init/calc/check) > ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut mode).unwrap();
    match &(mode.trim())[..] {
        "init" => init_phase(),
        "calc" => calc_phase().await,
        "check" => check_phase(),
        _ => panic!("Invalid mode"),
    }?;

    Ok(())
}

async fn calc_phase() -> Result<(), Box<dyn std::error::Error>> {
    println!("ローカルデータ読み込み中...");
    let (my_friends, _client_key) = load_local_secret_data().await.unwrap();

    println!("相手の暗号化済みフレンドリストの読み込み中...");
    let (remote_data, server_keys) = load_remote_data().await.unwrap();

    rayon::broadcast(|_| set_server_key(server_keys.clone()));
    set_server_key(server_keys);

    println!("暗号文の展開中（この処理には時間がかかります）...");
    let remote_friends: Vec<CompressedFheUint128> = remote_data.friends.par_iter().map(|f| &f.value).map(|v| bincode::deserialize(&v).unwrap()).collect();
    let remote_friends: Vec<FheUint128> = remote_friends.par_iter().map(|f| f.decompress()).collect();

    // calc time
    println!("共通フレンドの計算中...");
    let now = std::time::Instant::now();
    let all = my_friends.len() * remote_friends.len();
    let count = Mutex::new(0);
    let compared: Vec<Vec<FheBool>> = remote_friends.par_iter().enumerate().map(|(i, remote_friend)| {
        (0..my_friends.len()).into_par_iter().map(|j| {
            let result = remote_friend.eq(my_friends[j]);
            let mut count = count.lock().unwrap();
            *count += 1;
            println!("{} / {}", *count, all);
            result
        }).collect()
    }).collect();

    println!("圧縮中...");
    let mut result: Vec<FheBool> = Vec::new();
    for res in compared {
        result.push(res.par_iter().cloned().reduce_with(|acc, x| acc | x).unwrap());
    }

    let elapsed = now.elapsed();
    println!("計算時間: {}.{:03}秒", elapsed.as_secs(), elapsed.subsec_millis());

    println!("データの整形中...");
    let serialized_compared_friends: SerializedComparedFriends = SerializedComparedFriends { friends: result.iter().map(|f| SerializedComparedFriend { value: bincode::serialize(f).unwrap() }).collect() };

    println!("データの保存中...");
    let mut file = File::create("mutual_friends").unwrap();
    bincode::serialize_into(&mut file, &serialized_compared_friends).unwrap();

    Ok(())
}

fn check_phase() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn init_phase() -> Result<(), Box<dyn std::error::Error>> {
    let friends = get_friends();

    let config = ConfigBuilder::default().build();

    let (client_key, server_keys) = generate_keys(config);

    set_server_key(server_keys.clone());

    println!("フレンドリストを暗号化しています...");
    let encrypted_friends: Vec<FheUint128> = friends.iter().map(|f| FheUint128::try_encrypt(*f, &client_key).unwrap()).collect();
    
    println!("暗号文の圧縮中...");
    let compressed_friends: Vec<CompressedFheUint128> = encrypted_friends.iter().map(|f| f.compress()).collect();

    println!("データの整形中...");
    let serialized_friends: Vec<SerializedFriend> = compressed_friends.iter().map(|f| SerializedFriend { value: bincode::serialize(f).unwrap() }).collect();
    let serialized_friends = SerializedFriends { friends: serialized_friends };

    println!("公開データの整形中...");
    let mut public_serialized_data = Vec::new();
    bincode::serialize_into(&mut public_serialized_data, &serialized_friends).unwrap();
    bincode::serialize_into(&mut public_serialized_data, &server_keys).unwrap();

    println!("秘密データの整形中...");
    let mut private_serialized_data = Vec::new();
    bincode::serialize_into(&mut private_serialized_data, &friends).unwrap();
    bincode::serialize_into(&mut private_serialized_data, &client_key).unwrap();

    println!("データの保存中...");
    let mut public_file = File::create("public_data").unwrap();
    let mut private_file = File::create("secret_data").unwrap();

    let compressed_public_data = zstd::encode_all(&public_serialized_data[..], 9).unwrap();
    let compressed_private_data = zstd::encode_all(&private_serialized_data[..], 9).unwrap();

    public_file.write_all(&compressed_public_data).unwrap();
    private_file.write_all(&compressed_private_data).unwrap();

    Ok(())
}

fn get_friends() -> Vec<u128> {
    let mut vrc_config = Configuration::default();
    vrc_config.user_agent = Some("TFHE-Mutual-Friends 0.1.0".to_string());
    print!("ユーザー名を入力してください > ");
    std::io::stdout().flush().unwrap();
    let mut username = String::new();
    std::io::stdin().read_line(&mut username).unwrap();
    
    print!("パスワードを入力してください(入力文字は非表示) > ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    vrc_config.basic_auth = Some((username.trim().to_string(), Some(password.trim().to_string())));

    let me = match get_current_user(&vrc_config).unwrap() {
        vrchatapi::models::EitherUserOrTwoFactor::CurrentUser(user) => {
            println!("{:?}", user.username);
            user
        },
        vrchatapi::models::EitherUserOrTwoFactor::RequiresTwoFactorAuth(two_factor_auth_code) => {
            print!("2段階認証のコードを入力してください > ");
            std::io::stdout().flush().unwrap();
            let mut code = String::new();
            std::io::stdin().read_line(&mut code).unwrap();

            verify2_fa(&vrc_config, TwoFactorAuthCode::new(code)).unwrap();

            match get_current_user(&vrc_config).unwrap() {
                vrchatapi::models::EitherUserOrTwoFactor::CurrentUser(user) => {
                    user
                },
                vrchatapi::models::EitherUserOrTwoFactor::RequiresTwoFactorAuth(two_factor_auth_code) => {
                    panic!("2fa failed");
                }
            }
        }
    };
    let friends = me.friends;
    let friend_ids: Vec<u128> = friends.iter()
        .map(|friend| {
            let friend = friend.replace("usr_", "").replace("-", "");
            u128::from_str_radix(&friend, 16).unwrap()
        })
        .collect();
    friend_ids
}

fn u128_to_usr(id: u128) -> String {
    let a = format!("{:032x}", id);
    format!("usr_{}-{}-{}-{}-{}", &a[..8], &a[8..12], &a[12..16], &a[16..20], &a[20..])
}

async fn load_local_secret_data() -> Result<(Vec<u128>, ClientKey), Box<dyn std::error::Error>> {
    let buffer = fs::read("secret_data").await?;
    let mut decompressed = Vec::new();
    let mut decoder = zstd::stream::read::Decoder::new(&buffer[..])?;
    decoder.read_to_end(&mut decompressed)?;
    let mut cursor = std::io::Cursor::new(decompressed);
    let friends: Vec<u128> = bincode::deserialize_from(&mut cursor).unwrap();
    let client_key: ClientKey = bincode::deserialize_from(&mut cursor).unwrap();
    Ok((friends, client_key))
}

async fn load_remote_data() -> Result<(SerializedFriends, ServerKey), Box<dyn std::error::Error>> {
    let buffer = fs::read("download/public_data").await?;
    let mut decompressed = Vec::new();
    let mut decoder = zstd::stream::read::Decoder::new(&buffer[..])?;
    decoder.read_to_end(&mut decompressed)?;
    let mut cursor = std::io::Cursor::new(decompressed);
    let public_data: SerializedFriends = bincode::deserialize_from(&mut cursor).unwrap();
    let server_keys: ServerKey = bincode::deserialize_from(&mut cursor).unwrap();
    Ok((public_data, server_keys))
}

#[derive(Serialize, Deserialize)]
struct SerializedFriends {
    friends: Vec<SerializedFriend>,
}

#[derive(Serialize, Deserialize)]
struct SerializedFriend {
    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializedComparedFriends {
    friends: Vec<SerializedComparedFriend>,
}

#[derive(Serialize, Deserialize)]
struct SerializedComparedFriend {
    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}
