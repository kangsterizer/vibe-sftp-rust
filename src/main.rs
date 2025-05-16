// main.rs

use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::rc::Rc; // For Rc<RefCell<>>
use std::cell::RefCell; // For Rc<RefCell<>>

use ssh2::{Session, Sftp, OpenFlags}; // Removed FileStat import

// Import clap for command-line argument parsing
use clap::Parser;

// Import rustyline for interactive shell
use rustyline::completion::Completer; // Removed Candidate import
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper, Context, Result as RustylineResult};


/// A basic SFTP client mimicking some OpenSSH sftp options, now with an interactive shell and autocompletion.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// SFTP destination in the format [user@]host[:path]
    destination: String,

    /// Specifies the port to connect to on the remote host.
    #[arg(short = 'P', long, value_name = "PORT")]
    port: Option<u16>,

    /// Selects a file from which the identity (private key) for public key authentication is read.
    #[arg(short = 'i', long, value_name = "IDENTITY_FILE")]
    identity_file: Option<PathBuf>,

    /// Batch mode reads a series of commands from an input batchfile instead of stdin.
    /// If this is used, interactive mode is disabled.
    #[arg(short = 'b', long, value_name = "BATCH_FILE")]
    batchfile: Option<PathBuf>,

    /// Optional SFTP command to execute non-interactively.
    /// If this is used, interactive mode is disabled.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command_and_args: Vec<String>,
}

// Structure to hold parsed destination details (unchanged)
#[derive(Debug)]
struct SftpDestination {
    user: Option<String>,
    host: String,
    remote_path: Option<String>,
}

impl SftpDestination {
    fn parse(dest_str: &str) -> Result<Self, String> {
        let (user_host_part, remote_path) = match dest_str.split_once(':') {
            Some((uh, rp)) => (uh, Some(rp.to_string())),
            None => (dest_str, None),
        };
        let (user, host) = match user_host_part.split_once('@') {
            Some((u, h)) => (Some(u.to_string()), h.to_string()),
            None => (None, user_host_part.to_string()),
        };
        if host.is_empty() { return Err("Host part cannot be empty.".to_string()); }
        Ok(SftpDestination { user, host, remote_path })
    }
}

// SftpClient struct (unchanged definition)
struct SftpClient {
    session: Session,
    sftp: Sftp,
    current_remote_path: PathBuf,
    connected_host_string: String,
}

// SftpClient methods
impl SftpClient {
    pub fn connect(
        dest: &SftpDestination, port: u16, identity_file: Option<&Path>, password_override: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let host_with_port = format!("{}:{}", dest.host, port);
        let tcp = TcpStream::connect(&host_with_port)?;
        println!("Connecting to {}...", host_with_port);

        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;
        
        let user_string = dest.user.clone().unwrap_or_else(|| env::var("USER").unwrap_or_else(|_| "unknown_user".to_string()));
        let user: &str = &user_string;
        print!("Authenticating as {}... ", user);

        // Authentication logic (largely unchanged)
        if let Some(key_path) = identity_file {
            match session.userauth_pubkey_file(user, None, key_path, None) {
                Ok(_) => println!("Authenticated with public key: {}.", key_path.display()),
                Err(e) => {
                    print!("Public key auth failed ({}). ", key_path.display());
                    if let Some(password) = password_override {
                        session.userauth_password(user, password)?;
                        println!("Authenticated with provided password.");
                    } else { return Err(Box::new(e)); }
                }
            }
        } else if let Some(password) = password_override {
            session.userauth_password(user, password)?;
            println!("Authenticated with provided password.");
        } else {
            match session.userauth_agent(user) {
                Ok(_) => println!("Authenticated with SSH agent."),
                Err(e) => {
                    println!("SSH agent authentication failed: {}. No password provided.", e);
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Authentication failed.")));
                }
            }
        }

        if !session.authenticated() { return Err("Authentication failed.".into()); }
        
        let sftp = session.sftp()?;
        let initial_remote_path_str = dest.remote_path.as_deref().unwrap_or(".");
        // Type inference for stat_result, or use ssh2::FileStat explicitly if needed
        let stat_result = sftp.stat(Path::new(initial_remote_path_str));
        let canonical_initial_path = match stat_result {
            Ok(stat) => if stat.is_dir() { sftp.realpath(Path::new(initial_remote_path_str))? } else { Path::new(initial_remote_path_str).parent().map_or_else(|| sftp.realpath(Path::new(".")), |p| sftp.realpath(p))? },
            Err(_) => sftp.realpath(Path::new("."))?,
        };
        
        Ok(SftpClient { session, sftp, current_remote_path: canonical_initial_path, connected_host_string: host_with_port })
    }

    fn resolve_remote_path(&self, path_str: &str) -> PathBuf {
        let input_path = Path::new(path_str);
        if input_path.is_absolute() { input_path.to_path_buf() } else { self.current_remote_path.join(input_path) }
    }

    pub fn list_dir(&self, remote_path_str: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let path_to_list = remote_path_str.map(|p| self.resolve_remote_path(p)).unwrap_or_else(|| self.current_remote_path.clone());
        let entries = self.sftp.readdir(&path_to_list)?;
        if entries.is_empty() { println!("(empty directory)"); }
        for (path, stat) in entries {
            let file_type_char = if stat.is_dir() { "d" } else if stat.is_file() { "-" } else if stat.file_type().is_symlink() { "l" } else { "?" };
            println!("{:1}{:03o} {:>10} {}", file_type_char, stat.perm.unwrap_or(0) & 0o777, stat.size.unwrap_or(0), path.file_name().unwrap_or_default().to_string_lossy());
        }
        Ok(())
    }

    pub fn upload_file(&self, local_path_str: &str, remote_dest_str: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let local_path = Path::new(local_path_str);
        if !local_path.exists() { return Err(format!("Local file not found: {}", local_path.display()).into()); }
        if !local_path.is_file() { return Err(format!("Local path is not a file: {}", local_path.display()).into()); }
        
        let local_filename_osstr = local_path.file_name().ok_or("Could not get local filename")?;
        let local_filename_for_check = local_filename_osstr.to_string_lossy().to_lowercase();


        let mut final_remote_path = remote_dest_str.map(|d| self.resolve_remote_path(d)).unwrap_or_else(|| self.current_remote_path.clone());
        if self.sftp.stat(&final_remote_path).map_or(false, |s| s.is_dir()) || remote_dest_str.is_none() { 
            final_remote_path.push(local_filename_osstr); 
        }

        println!("Uploading '{}' to '{}'", local_path.display(), final_remote_path.display());

        if local_filename_for_check.contains("jeff") || local_filename_for_check.contains("stefan") {
            println!("booooyaa");
        }

        let mut local_file = File::open(local_path)?;
        let mut remote_file = self.sftp.open_mode(&final_remote_path, OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE, 0o644, ssh2::OpenType::File)?;
        let bytes_copied = std::io::copy(&mut local_file, &mut remote_file)?;
        println!("Uploaded {} bytes.", bytes_copied);
        Ok(())
    }

    pub fn download_file(&self, remote_src_str: &str, local_dest_str: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = self.resolve_remote_path(remote_src_str);
        let remote_filename = remote_path.file_name().ok_or_else(|| format!("Could not get remote filename: {}", remote_path.display()))?;
        let mut local_path_buf = env::current_dir()?;
        if let Some(dest_str) = local_dest_str {
            let p = PathBuf::from(dest_str);
            if p.is_dir() || dest_str.ends_with('/') || dest_str.ends_with(std::path::MAIN_SEPARATOR) { local_path_buf = p; local_path_buf.push(remote_filename); } else { local_path_buf = p; }
        } else { local_path_buf.push(remote_filename); }
        if let Some(parent_dir) = local_path_buf.parent() { if !parent_dir.exists() { std::fs::create_dir_all(parent_dir)?; } }

        println!("Downloading '{}' to '{}'", remote_path.display(), local_path_buf.display());
        let stat = self.sftp.stat(&remote_path).map_err(|e| format!("Remote file '{}' not found: {}", remote_path.display(), e))?;
        if !stat.is_file() { return Err(format!("Remote path '{}' is not a file.", remote_path.display()).into()); }
        let mut remote_file = self.sftp.open(&remote_path)?;
        let mut local_file = File::create(&local_path_buf)?;
        let bytes_copied = std::io::copy(&mut remote_file, &mut local_file)?;
        println!("Downloaded {} bytes to '{}'.", bytes_copied, local_path_buf.display());
        Ok(())
    }
    
    // cd_remote now takes &mut self, will be called via client.borrow_mut()
    pub fn cd_remote(&mut self, remote_path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let new_path_candidate = self.resolve_remote_path(remote_path_str); // Uses self.current_remote_path
        match self.sftp.realpath(&new_path_candidate) {
            Ok(canonical_path) => match self.sftp.stat(&canonical_path) {
                Ok(stat) if stat.is_dir() => { self.current_remote_path = canonical_path; Ok(()) } // Mutates self
                Ok(_) => Err(format!("Not a directory: {}", new_path_candidate.display()).into()),
                Err(e) => Err(format!("Cannot stat remote path {}: {}", new_path_candidate.display(), e).into()),
            },
            Err(e) => Err(format!("Invalid remote path {}: {}", new_path_candidate.display(), e).into()),
        }
    }

    pub fn pwd_remote(&self) { println!("Remote directory: {}", self.current_remote_path.display()); }

    pub fn rm_file(&self, remote_file_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = self.resolve_remote_path(remote_file_str);
        self.sftp.unlink(&remote_path)?; println!("Removed remote file: {}", remote_path.display()); Ok(())
    }

    pub fn mkdir_remote(&self, remote_dir_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = self.resolve_remote_path(remote_dir_str);
        self.sftp.mkdir(&remote_path, 0o755)?; println!("Created remote directory: {}", remote_path.display()); Ok(())
    }

    pub fn rmdir_remote(&self, remote_dir_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let remote_path = self.resolve_remote_path(remote_dir_str);
        self.sftp.rmdir(&remote_path)?; println!("Removed remote directory: {}", remote_path.display()); Ok(())
    }

    // No explicit disconnect method needed if relying on RAII for Session and Sftp.
    // If we want an explicit one that consumes, it would be `fn disconnect(self) ...`
    // For now, let RAII handle it when the Rc<RefCell<SftpClient>> is dropped.
}

// --- Autocompletion Logic ---
struct SftpCompleter { // No longer generic over lifetime 'a
    client: Rc<RefCell<SftpClient>>, // Store Rc<RefCell<SftpClient>>
    commands: Vec<String>,
}

impl SftpCompleter { // No longer generic over lifetime 'a
    fn new(client: Rc<RefCell<SftpClient>>) -> Self { // Takes Rc<RefCell<SftpClient>>
        SftpCompleter {
            client,
            commands: vec![
                "ls", "dir", "get", "put", "cd", "pwd", "rm", "mkdir", "rmdir", "help", "?", "exit", "quit", "bye",
            ].into_iter().map(String::from).collect(),
        }
    }
}

impl Completer for SftpCompleter { // No longer generic over lifetime 'a
    type Candidate = String;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> RustylineResult<(usize, Vec<Self::Candidate>)> {
        let client = self.client.borrow(); // Immutable borrow for reading state

        let words: Vec<&str> = line[..pos].split_whitespace().collect();
        let mut current_word_start = 0;
        if let Some(last_space) = line[..pos].rfind(char::is_whitespace) {
            current_word_start = last_space + 1;
        } else if !line.is_empty() && pos > 0 && !line.starts_with(char::is_whitespace) {
            current_word_start = 0;
        } else if pos > 0 {
            current_word_start = pos;
        }

        // Command completion
        if words.is_empty() || (words.len() == 1 && pos >= current_word_start && !line[current_word_start..pos].is_empty()) || (words.len() == 1 && line.chars().last().map_or(false, |c| !c.is_whitespace() && pos > current_word_start )) {
            let current_typing = &line[current_word_start..pos];
            let mut candidates: Vec<String> = self.commands.iter()
                .filter(|cmd| cmd.starts_with(current_typing))
                .cloned()
                .collect();
            
            if candidates.len() == 1 && candidates[0] == current_typing && !current_typing.is_empty() {
                candidates[0].push(' ');
            }
            return Ok((current_word_start, candidates));
        }

        // Argument completion (remote paths)
        if let Some(command_str) = words.get(0) {
            let remote_path_commands = ["ls", "dir", "cd", "get", "rm", "mkdir", "rmdir"];
            let put_command_str = "put";

            // Determine if we are completing a remote path argument
            let needs_remote_completion = remote_path_commands.contains(command_str) || 
                                          (command_str == &put_command_str && words.len() > 1 && pos > words[0].len());
            
            if needs_remote_completion {
                let path_arg_index = if command_str == &put_command_str { 2 } else { 1 };

                if words.len() >= path_arg_index {
                    let mut arg_word_start = 0;
                    let mut current_arg_text = "";

                    // Find the start of the current argument being typed
                    let mut char_idx_count = 0;
                    let mut word_idx_count = 0;
                    for word in line.split_whitespace() {
                        word_idx_count += 1;
                        if word_idx_count == path_arg_index {
                            arg_word_start = char_idx_count;
                            // Check if cursor is within or at the end of this argument word
                            if pos >= arg_word_start {
                                current_arg_text = &line[arg_word_start .. pos.min(arg_word_start + word.len())];
                                if pos > arg_word_start + word.len() && line.chars().nth(arg_word_start + word.len()) == Some(' ') {
                                     // Cursor is after this argument and a space, so no completion for *this* arg
                                    current_arg_text = ""; // Effectively, start new completion
                                    arg_word_start = pos;
                                } else if pos > arg_word_start + word.len() {
                                     // Cursor is after this argument but no space, so no completion for *this* arg
                                     current_arg_text = "";
                                     arg_word_start = pos;
                                } else {
                                     current_arg_text = &line[arg_word_start..pos];
                                }
                            } else {
                                // Cursor is before this argument, no completion for this arg
                                current_arg_text = "";
                                arg_word_start = pos;
                            }
                            break;
                        }
                        char_idx_count += word.len() + 1; // +1 for space
                    }
                     // If no specific argument was found (e.g. "ls " then TAB), arg_word_start is pos, current_arg_text is ""
                    if word_idx_count < path_arg_index && pos > 0 && line.chars().nth(pos-1).map_or(false, |c| c.is_whitespace()) {
                        arg_word_start = pos;
                        current_arg_text = "";
                    }


                    let partial_path = current_arg_text;
                        
                    let (base_dir_to_list, prefix_to_match) = if partial_path.contains('/') {
                        let mut components = PathBuf::from(partial_path);
                        let prefix = components.file_name().unwrap_or_default().to_string_lossy().to_string();
                        components.pop();
                        (client.resolve_remote_path(components.to_str().unwrap_or(".")), prefix)
                    } else {
                        (client.current_remote_path.clone(), partial_path.to_string())
                    };
                    
                    let mut candidates = Vec::new();
                    if let Ok(entries) = client.sftp.readdir(&base_dir_to_list) {
                        for (path_buf, stat) in entries {
                            if let Some(name_osstr) = path_buf.file_name() {
                                let name = name_osstr.to_string_lossy();
                                if name.starts_with(&prefix_to_match) {
                                    let mut suggestion = name.into_owned();
                                    if stat.is_dir() {
                                        suggestion.push('/');
                                    }
                                    candidates.push(suggestion);
                                }
                            }
                        }
                    }
                    return Ok((arg_word_start, candidates));
                }
            }
        }
        Ok((pos, Vec::new()))
    }
}

impl Hinter for SftpCompleter { type Hint = String; } // No hints for now
impl Highlighter for SftpCompleter { } // Default highlighting
impl Validator for SftpCompleter { } // No validation for now
impl Helper for SftpCompleter {}


fn print_help() { 
    println!("Available commands:");
    println!("  ls [path]            List remote directory contents");
    println!("  cd <path>            Change remote working directory");
    println!("  pwd                  Print remote working directory");
    println!("  get <remote> [local] Download file from remote to local");
    println!("  put <local> [remote] Upload file from local to remote");
    println!("  rm <remote_file>     Remove remote file");
    println!("  mkdir <remote_dir>   Create remote directory");
    println!("  rmdir <remote_dir>   Remove remote directory (must be empty)");
    println!("  help                 Show this help message");
    println!("  exit, quit, bye      Disconnect and exit");
}

// process_command now takes &Rc<RefCell<SftpClient>>
fn process_command(client_rc: &Rc<RefCell<SftpClient>>, command_parts: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if command_parts.is_empty() { return Ok(()); }
    let command = command_parts[0].to_lowercase();
    let args = &command_parts[1..];

    // Methods that don't mutate SftpClient's direct state (like current_remote_path) can use borrow()
    // Methods that do mutate (like cd_remote) need borrow_mut()
    match command.as_str() {
        "ls" | "dir" => client_rc.borrow().list_dir(args.get(0).map(String::as_str))?,
        "get" => { 
            if args.is_empty() { return Err("get: missing <remote_file>".into()); } 
            client_rc.borrow().download_file(&args[0], args.get(1).map(String::as_str))?; 
        }
        "put" => { 
            if args.is_empty() { return Err("put: missing <local_file>".into()); } 
            client_rc.borrow().upload_file(&args[0], args.get(1).map(String::as_str))?; 
        }
        "cd" => { 
            if args.is_empty() { return Err("cd: missing <remote_path>".into()); } 
            client_rc.borrow_mut().cd_remote(&args[0])?; // cd_remote mutates current_remote_path
        }
        "pwd" => client_rc.borrow().pwd_remote(),
        "rm" => { 
            if args.is_empty() { return Err("rm: missing <remote_file>".into()); } 
            client_rc.borrow().rm_file(&args[0])?; 
        }
        "mkdir" => { 
            if args.is_empty() { return Err("mkdir: missing <remote_dir>".into()); } 
            client_rc.borrow().mkdir_remote(&args[0])?; 
        }
        "rmdir" => { 
            if args.is_empty() { return Err("rmdir: missing <remote_dir>".into()); } 
            client_rc.borrow().rmdir_remote(&args[0])?; 
        }
        "help" | "?" => print_help(),
        "exit" | "quit" | "bye" => return Err("exit_command".into()),
        _ => eprintln!("Unknown command: '{}'. Type 'help'.", command),
    }
    Ok(())
}

// interactive_shell now takes Rc<RefCell<SftpClient>>
fn interactive_shell(client_rc: Rc<RefCell<SftpClient>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connected to {}. Type 'help' for commands.", client_rc.borrow().connected_host_string);
    client_rc.borrow().pwd_remote();

    let completer = SftpCompleter::new(client_rc.clone()); // Clone Rc for completer
    let mut rl = Editor::new()?;
    rl.set_helper(Some(completer));
    // Optional: Load/save history
    // if rl.load_history("sftp_history.txt").is_err() { /* ... */ }

    loop {
        let prompt = { // Create prompt within a new scope to drop borrow of client_rc sooner
            let client_borrow = client_rc.borrow();
            let current_dir_name = client_borrow.current_remote_path.file_name().unwrap_or_default().to_string_lossy();
            format!("sftp:{}> ", if current_dir_name.is_empty() { "/" } else { &current_dir_name } )
        };
        
        match rl.readline(&prompt) {
            Ok(line) => {
                if !line.trim().is_empty() {
                    let _ = rl.add_history_entry(line.as_str());
                }
                let trimmed_line = line.trim();
                if trimmed_line.is_empty() { continue; }
                let command_parts: Vec<String> = trimmed_line.split_whitespace().map(String::from).collect();
                
                // Pass the Rc to process_command
                match process_command(&client_rc, &command_parts) {
                    Ok(_) => {}
                    Err(e) if e.to_string() == "exit_command" => { println!("Exiting."); break; }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => { println!("^C"); }
            Err(ReadlineError::Eof) => { println!("exit"); break; }
            Err(err) => { eprintln!("Readline error: {:?}", err); break; }
        }
    }
    // if let Err(err) = rl.save_history("sftp_history.txt") { /* ... */ }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let dest_info = SftpDestination::parse(&cli.destination).map_err(|e| format!("Invalid destination: {}", e))?;
    let port = cli.port.unwrap_or(22);
    let sftp_pass = env::var("SFTP_PASS").ok();

    println!("--- Rust SFTP Client ---");
    
    // Create the SftpClient and wrap it in Rc<RefCell<>>
    let client_rc = Rc::new(RefCell::new(SftpClient::connect(
        &dest_info, 
        port, 
        cli.identity_file.as_deref(), 
        sftp_pass.as_deref()
    )?));

    // Batch mode and single command mode will also use the Rc<RefCell<SftpClient>>
    if let Some(batch_path) = cli.batchfile {
        println!("\nProcessing Batch File: {}", batch_path.display());
        client_rc.borrow().pwd_remote(); // Initial PWD
        let file = File::open(batch_path)?;
        for line_result in io::BufReader::new(file).lines() {
            let line = line_result?.trim().to_string();
            if line.is_empty() || line.starts_with('#') { continue; }
            println!("sftp> {}", line);
            let command_parts: Vec<String> = line.split_whitespace().map(String::from).collect();
            match process_command(&client_rc, &command_parts) {
                Ok(_) => {}
                Err(e) if e.to_string() == "exit_command" => { println!("Exit from batch."); break; }
                Err(e) => eprintln!("Error (batch): {}", e),
            }
        }
    } else if !cli.command_and_args.is_empty() {
        println!("\nExecuting Single Command:");
        client_rc.borrow().pwd_remote(); // Initial PWD
        println!("sftp> {}", cli.command_and_args.join(" "));
        match process_command(&client_rc, &cli.command_and_args) {
            Ok(_) => {}
            Err(e) if e.to_string() == "exit_command" => {}
            Err(e) => eprintln!("Error (command): {}", e),
        }
    } else {
        // Pass the Rc to interactive_shell
        if let Err(e) = interactive_shell(client_rc.clone()) { // Clone Rc for interactive shell
            eprintln!("Interactive shell exited with error: {}", e);
        }
    }

    // When client_rc (and all its clones) go out of scope, SftpClient will be dropped.
    // The SftpClient's drop implementation (if any) or its fields' (Session, Sftp) drop
    // will handle resource cleanup.
    println!("\nDisconnecting from {}.", client_rc.borrow().connected_host_string);
    // No explicit client.disconnect() needed if relying on RAII and Rc/RefCell drop.
    // If SftpClient had an explicit disconnect that consumed self, managing that with Rc<RefCell>
    // would require taking the client out of the RefCell, which is more complex.
    // For now, assume RAII is sufficient for Session/Sftp drop.
    Ok(())
}

/*
----------------------------------------------------
            Cargo.toml dependencies
----------------------------------------------------
[dependencies]
ssh2 = "0.9"
clap = { version = "4.4", features = ["derive"] }
rustyline = "13.0" # Or latest version

----------------------------------------------------
            How to Compile and Run
----------------------------------------------------
1. Save the code as `src/main.rs`.
2. Update `Cargo.toml` (ensure versions are compatible).
3. Build: `cargo build`
4. Run in Interactive Mode:
   `cargo run -- your_user@your_host`
*/
