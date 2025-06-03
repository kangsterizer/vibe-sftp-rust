// main.rs

use std::env;
use std::fs::File; // Still needed for batch file processing in main
use std::io::{self, BufRead}; // Still needed for batch file processing in main
use std::rc::Rc;
use std::cell::RefCell;

// Use items from our library crate
use rust_sftp_client::{
    Cli,            // The command-line interface parser
    SftpClient,     // The main client logic
    SftpDestination,// For parsing the destination string
    process_command, // For handling individual commands (batch/single)
    interactive_shell, // For the interactive mode
    Parser,          // Re-exported from lib.rs for Cli::parse()
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let dest_info = SftpDestination::parse(&cli.destination)
        .map_err(|e| format!("Invalid destination: {}", e))?;

    let port = cli.port.unwrap_or(22);
    let sftp_pass = env::var("SFTP_PASS").ok();

    println!("--- Rust SFTP Client ---");
    
    let client_rc = Rc::new(RefCell::new(SftpClient::connect(
        &dest_info, 
        port, 
        cli.identity_file.as_deref(), 
        sftp_pass.as_deref()
    )?));

    if let Some(batch_path) = cli.batchfile {
        println!("\nProcessing Batch File: {}", batch_path.display());
        client_rc.borrow().pwd_remote();
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
        client_rc.borrow().pwd_remote();
        println!("sftp> {}", cli.command_and_args.join(" "));
        match process_command(&client_rc, &cli.command_and_args) {
            Ok(_) => {}
            Err(e) if e.to_string() == "exit_command" => {} // Don't print "Exiting." for single command
            Err(e) => eprintln!("Error (command): {}", e),
        }
    } else {
        if let Err(e) = interactive_shell(client_rc.clone()) {
            // "exit_command" is handled within interactive_shell, other errors are actual problems
            if e.to_string() != "exit_command" {
                 eprintln!("Interactive shell exited with error: {}", e);
            }
        }
    }

    println!("\nDisconnecting from {}.", client_rc.borrow().connected_host_string);
    Ok(())
}
