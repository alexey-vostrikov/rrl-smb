//! The logon a Windows machine makes before it has a ticket.
//!
//! `Add-Computer` cannot present a Kerberos ticket for a domain it has not joined - the domain has
//! not issued it one - so its first `SESSION_SETUP` is NTLM against a real account. Measured on the
//! AD-join stand: a server whose static user table is empty answered `NT proof mismatch` for a
//! password that was right, and the guest reported "the user name or password is incorrect".

#![cfg(feature = "localfs")]

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;

use common::auth::{Login, spnego_login};
use common::{negotiate, start_server};
use smb_server::ntstatus::{STATUS_LOGON_FAILURE, STATUS_SUCCESS};
use smb_server::{LogonUsers, SmbServer, UserCreds};
use tokio::net::TcpStream;

/// A directory of accounts, as the daemon that owns one would hand it over.
#[derive(Debug)]
struct Directory(HashMap<String, UserCreds>);

impl LogonUsers for Directory {
    fn user(&self, account: &str) -> Option<UserCreds> {
        // Case-insensitive, as `sAMAccountName` is in the directory this stands for.
        self.0.get(&account.to_ascii_lowercase()).cloned()
    }
}

fn directory() -> Directory {
    let mut accounts = HashMap::new();
    accounts.insert(
        "carol".to_string(),
        UserCreds::from_password("correct horse battery staple"),
    );
    Directory(accounts)
}

async fn server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // No `.user(...)`: the point is that the account is not in the static table at all, which is the
    // state a deployment is in when its accounts live in the directory.
    start_server(
        SmbServer::builder()
            .share_listing(true)
            .logon_users(std::sync::Arc::new(directory())),
    )
    .await
}

async fn logon(addr: SocketAddr, user: &str, password: &str) -> Login {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut stream).await;
    spnego_login(&mut stream, 1, 0, user, password).await
}

#[tokio::test]
async fn an_account_from_the_directory_logs_on_without_being_configured() {
    let (addr, task) = server().await;
    let login = logon(addr, "carol", "correct horse battery staple").await;
    assert_eq!(
        login.status, STATUS_SUCCESS,
        "a domain account's NTLM logon is checked against the directory"
    );
    assert_ne!(login.session_id, 0, "a completed logon has a session");
    task.abort();
}

/// A wrong password and an account that does not exist answer identically: a client that could tell
/// them apart could enumerate the domain's accounts.
#[tokio::test]
async fn a_wrong_password_and_an_unknown_account_are_indistinguishable() {
    let (addr, task) = server().await;
    let wrong = logon(addr, "carol", "not the password").await;
    let unknown = logon(addr, "dave", "correct horse battery staple").await;
    assert_eq!(wrong.status, STATUS_LOGON_FAILURE);
    assert_eq!(
        unknown.status, wrong.status,
        "an unknown account gives the same answer as a wrong password"
    );
    // Deliberately not comparing session ids: this very pair shows the id is a counter that moves on
    // every failure (1 then 2 here), so it carries nothing about the account. The status is the only
    // thing a client can read, and it is the same.
    task.abort();
}

/// The static table answers first and cannot be shadowed by a directory that happens to hold the
/// same name - it is what the deployment configured, and a directory is not the authority over it.
#[tokio::test]
async fn a_configured_user_keeps_the_password_the_deployment_gave_it() {
    let mut accounts = HashMap::new();
    accounts.insert(
        "alice".to_string(),
        UserCreds::from_password("from-the-directory"),
    );
    let (addr, task) = start_server(
        SmbServer::builder()
            .user("alice", "from-the-configuration")
            .logon_users(std::sync::Arc::new(Directory(accounts))),
    )
    .await;

    let configured = logon(addr, "alice", "from-the-configuration").await;
    assert_eq!(configured.status, STATUS_SUCCESS);
    let shadowed = logon(addr, "alice", "from-the-directory").await;
    assert_eq!(
        shadowed.status, STATUS_LOGON_FAILURE,
        "the configured password is the one this deployment serves"
    );
    task.abort();
}

/// Case does not have to match: a Windows client sends the name the way the account is written, and
/// `sAMAccountName` is compared case-insensitively by the directory that owns it.
#[tokio::test]
async fn the_account_name_is_matched_without_regard_to_case() {
    let (addr, task) = server().await;
    let login = logon(addr, "Carol", "correct horse battery staple").await;
    assert_eq!(login.status, STATUS_SUCCESS);
    task.abort();
}
