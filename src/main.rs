// main.rs

use std::env;
use std::fs::File;
use std::io::Write; // Keep Write for File::create and local_file.write_all in main
use std::net::TcpStream;
use std::path::Path;
use ssh2::{Session, Sftp, OpenFlags}; // Removed FileType import

// Define a struct to hold SFTP client details
struct SftpClient {
    session: Session,
    sftp: Sftp,
}

impl SftpClient {
    /// Connects to an SFTP server and authenticates.
    pub fn connect(host: &str, username: &str, password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let tcp = TcpStream::connect(host)?;
        println!("Connected to TCP stream at {}", host);

        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;
        println!("SSH handshake completed.");

        session.userauth_password(username, password)?;
        println!("Authenticated with username: {}", username);

        if !session.authenticated() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Authentication failed",
            )));
        }
        println!("Authentication successful.");

        let sftp = session.sftp()?;
        println!("SFTP subsystem initialized.");

        Ok(SftpClient { session, sftp })
    }

    /// Lists files and directories in a remote path.
    pub fn list_dir(&self, remote_path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = Path::new(remote_path_str);
        println!("Listing directory: {:?}", remote_path);

        let entries = self.sftp.readdir(remote_path)?;
        println!("Found {} entries in '{}':", entries.len(), remote_path_str);

        for (path, stat) in entries {
            // `stat.file_type()` returns an object that has `is_symlink()` method.
            // No need to import `FileType` enum directly for this usage.
            let file_type_description = if stat.is_dir() {
                "Directory"
            } else if stat.is_file() {
                "File"
            } else if stat.file_type().is_symlink() { // Check for symlink
                "Symlink"
            } else {
                "Other"
            };
            println!(
                "- {:?} ({}, Size: {} bytes, Mode: {:o})",
                path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("N/A")),
                file_type_description,
                stat.size.unwrap_or(0),
                stat.perm.unwrap_or(0)
            );
        }
        Ok(())
    }

    /// Uploads a local file to a remote path.
    pub fn upload_file(&self, local_path_str: &str, remote_path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let local_path = Path::new(local_path_str);
        let remote_path = Path::new(remote_path_str);

        println!(
            "Attempting to upload '{}' to '{}'",
            local_path.display(),
            remote_path.display()
        );

        let mut local_file = File::open(local_path)?;

        // Corrected OpenFlags: Use WRITE instead of WRONLY
        let mut remote_file = self.sftp.open_mode(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE, // Corrected: WRITE
            0o644,
            ssh2::OpenType::File,
        )?;
        println!("Remote file created/opened for writing with mode 0o644.");

        let bytes_copied = std::io::copy(&mut local_file, &mut remote_file)?;
        println!(
            "Successfully wrote {} bytes from '{}' to '{}'",
            bytes_copied,
            local_path.display(),
            remote_path.display()
        );

        println!("Upload complete.");
        Ok(())
    }

    /// Downloads a remote file to a local path.
    pub fn download_file(&self, remote_path_str: &str, local_path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = Path::new(remote_path_str);
        let local_path = Path::new(local_path_str);

        println!(
            "Attempting to download '{}' to '{}'",
            remote_path.display(),
            local_path.display()
        );

        // Get file statistics first for display (optional, but good for user feedback)
        // sftp.stat() returns Result<FileStat, Error>
        let stat = match self.sftp.stat(remote_path) {
            Ok(s) => s,
            Err(e) => {
                // If stat fails, we might still try to open, or just error out.
                // For simplicity, we'll error out here.
                eprintln!("Could not get stats for remote file '{}': {}", remote_path.display(), e);
                return Err(Box::new(e));
            }
        };

        println!(
            "Remote file '{}' stats retrieved. Size: {} bytes. Proceeding to open.",
            remote_path.display(),
            stat.size.unwrap_or(0)
        );

        // Open the remote file for reading. sftp.open() returns Result<ssh2::File, Error>
        let mut remote_file = self.sftp.open(remote_path)?;
        println!("Remote file '{}' opened for reading.", remote_path.display());


        let mut local_file = File::create(local_path)?;
        println!("Local file '{}' created/opened for writing.", local_path.display());

        let bytes_copied = std::io::copy(&mut remote_file, &mut local_file)?;
        println!(
            "Successfully wrote {} bytes from '{}' to '{}'",
            bytes_copied,
            remote_path.display(),
            local_path.display()
        );

        println!("Download complete.");
        Ok(())
    }

    /// Disconnects the SFTP session.
    pub fn disconnect(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("SFTP client disconnecting. Resources will be cleaned up by RAII.");
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sftp_host = env::var("SFTP_HOST").unwrap_or_else(|_| "test.rebex.net:22".to_string());
    let sftp_user = env::var("SFTP_USER").unwrap_or_else(|_| "demo".to_string());
    let sftp_pass = env::var("SFTP_PASS").unwrap_or_else(|_| "password".to_string());

    let remote_dir_to_list = "pub/example";
    let local_file_to_upload = "local_upload_test.txt";
    let remote_upload_path = "pub/example/remote_upload_test_rust.txt";
    let remote_file_to_download = "pub/example/readme.txt";
    let local_download_path = "downloaded_readme_rust.txt";

    println!("--- SFTP Client Example ---");
    println!("Connecting to: {} as {}", sftp_host, sftp_user);
    if sftp_pass == "password" && sftp_host == "test.rebex.net:22" {
        println!("Using default credentials for test.rebex.net. This is a public test server.");
    } else if env::var("SFTP_PASS").is_err() {
         println!("WARNING: Using hardcoded default password. Set SFTP_PASS env var for your server.");
    }

    if !Path::new(local_file_to_upload).exists() {
        let mut f = File::create(local_file_to_upload)?;
        f.write_all(b"This is a test file for SFTP upload from Rust.\nHello, World from Rust SFTP client!")?;
        println!("Created dummy file: {}", local_file_to_upload);
    }

    let client = match SftpClient::connect(&sftp_host, &sftp_user, &sftp_pass) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error connecting to SFTP server: {}", e);
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                eprintln!("IO Error details: {:?}", io_err.kind());
            } else if let Some(ssh_err) = e.downcast_ref::<ssh2::Error>() {
                eprintln!("SSH Error details: code={}, msg={}", ssh_err.code(), ssh_err.message());
            }
            return Err(e);
        }
    };
    println!("\nSuccessfully connected to SFTP server!");

    println!("\n--- Listing Remote Directory: {} ---", remote_dir_to_list);
    if let Err(e) = client.list_dir(remote_dir_to_list) {
        eprintln!("Error listing directory '{}': {}", remote_dir_to_list, e);
    }

    println!("\n--- Uploading File ---");
    println!("Local: {}, Remote: {}", local_file_to_upload, remote_upload_path);
    if let Err(e) = client.upload_file(local_file_to_upload, remote_upload_path) {
        eprintln!(
            "Error uploading file '{}' to '{}': {}",
            local_file_to_upload, remote_upload_path, e
        );
    } else {
        println!("File uploaded successfully.");
        println!("\n--- Listing Remote Directory Again to see uploaded file: {} ---", remote_dir_to_list);
         if let Err(e) = client.list_dir(remote_dir_to_list) {
            eprintln!("Error listing directory '{}': {}", remote_dir_to_list, e);
        }
    }

    println!("\n--- Downloading File ---");
    println!("Remote: {}, Local: {}", remote_file_to_download, local_download_path);
    if let Err(e) = client.download_file(remote_file_to_download, local_download_path) {
        eprintln!(
            "Error downloading file '{}' to '{}': {}",
            remote_file_to_download, local_download_path, e
        );
    } else {
        println!("File downloaded successfully to '{}'.", local_download_path);
        match std::fs::read_to_string(local_download_path) {
            Ok(contents) => {
                println!("Contents of downloaded file (first 200 chars):");
                // Removed char_count, directly iterate and take 200 chars.
                for c in contents.chars().take(200) {
                    print!("{}", c);
                }
                if contents.chars().count() > 200 {
                    print!("...");
                }
                println!();
            }
            Err(e) => eprintln!("Could not read downloaded file: {}", e),
        }
    }

    println!("\n--- Disconnecting ---");
    if let Err(e) = client.disconnect() {
        eprintln!("Error during explicit disconnect (should be handled by drop): {}", e);
    } else {
        println!("Disconnected (or rather, client object consumed and resources will be dropped).");
    }

    Ok(())
}

/*
----------------------------------------------------
            Cargo.toml dependencies
----------------------------------------------------
[dependencies]
ssh2 = "0.9" # Check for the latest version on crates.io

----------------------------------------------------
            How to Compile and Run
----------------------------------------------------
1. Save the code as `src/main.rs`.
2. Create `Cargo.toml`:
   ```toml
   [package]
   name = "rust_sftp_client"
   version = "0.1.0"
   edition = "2021"

   [dependencies]
   ssh2 = "0.9" # Or "0.9.5"
   ```
3. Configure Server (use environment variables for your server):
   export SFTP_HOST="your.sftp.server.com:22"
   export SFTP_USER="your_username"
   export SFTP_PASS="your_password"
   (Defaults to test.rebex.net if variables are not set)
4. Build: `cargo build`
5. Run: `cargo run`
*/