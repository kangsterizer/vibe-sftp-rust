// tests/sftp_tests.rs

use rust_sftp_client::SftpDestination;
use rust_sftp_client::resolve_sftp_path;
use rust_sftp_client::{Cli, Parser, SftpClient}; // Added SftpClient here
use std::path::{Path, PathBuf};
use ssh2::{FileStat, Error as SshError, ErrorCode, OpenFlags, OpenType, File as SshFile};
use mockall::{mock, predicate::*}; // For mock! and predicates like eq()

// --- Manual Mock Definition using mockall::mock! ---
// This mock will implement the SftpOperations trait.
// The SftpOperations trait is defined in src/lib.rs (rust_sftp_client crate).
// We need to qualify it if this file is treated as a different crate.
// However, for tests in the `tests` directory, `rust_sftp_client` refers to the library crate.
mock! {
    pub SftpOps { // Struct name will be MockSftpOps
        // Methods from SftpOperations trait
        // Lifetimes need to be handled if the trait methods have them.
        // The SftpOperations trait methods do not have explicit lifetimes beyond '&self' and '&Path'.
        // mockall handles these for common cases. If complex lifetimes are involved,
        // they might need to be specified here (e.g., fn method<'a>(&self, input: &'a str) -> &'a str).
    }
    // Specify the trait to implement.
    // The path to SftpOperations is rust_sftp_client::SftpOperations
    impl rust_sftp_client::SftpOperations for SftpOps {
        fn readdir(&self, path: &Path) -> Result<Vec<(PathBuf, FileStat)>, SshError>;
        fn stat(&self, path: &Path) -> Result<FileStat, SshError>;
        fn realpath(&self, path: &Path) -> Result<PathBuf, SshError>;
        fn open_mode(&self, path: &Path, flags: OpenFlags, mode: i32, open_type: OpenType) -> Result<SshFile, SshError>;
        fn unlink(&self, file: &Path) -> Result<(), SshError>;
        fn mkdir(&self, path: &Path, mode: i32) -> Result<(), SshError>;
        fn rmdir(&self, path: &Path) -> Result<(), SshError>;
        fn open(&self, path: &Path) -> Result<SshFile, SshError>;
    }
}


#[cfg(test)]
mod sftp_destination_tests {
    use super::*; // Imports SftpDestination, etc.

    #[test]
    fn parse_host_only() {
        let dest_str = "example.com";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.remote_path, None);
    }

    #[test]
    fn parse_user_host() {
        let dest_str = "user@example.com";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("user".to_string()));
        assert_eq!(result.remote_path, None);
    }

    #[test]
    fn parse_host_path() {
        let dest_str = "example.com:/remote/path";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.remote_path, Some("/remote/path".to_string()));
    }

    #[test]
    fn parse_user_host_path() {
        let dest_str = "user@example.com:/remote/path";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("user".to_string()));
        assert_eq!(result.remote_path, Some("/remote/path".to_string()));
    }

    #[test]
    fn parse_empty_host_error() {
        let dest_str = "@:/path";
        let result = SftpDestination::parse(dest_str);
        assert!(result.is_err(), "Parsing should fail for empty host");
        assert_eq!(result.err(), Some("Host part cannot be empty.".to_string()));
    }

    #[test]
    fn parse_host_empty_path() {
        let dest_str = "example.com:";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.remote_path, Some("".to_string()));
    }

    #[test]
    fn parse_just_host_with_colon_empty_path() {
        let dest_str = "host:";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "host");
        assert_eq!(result.user, None);
        assert_eq!(result.remote_path, Some("".to_string()));
    }

    #[test]
    fn parse_user_at_host_with_colon_empty_path() {
        let dest_str = "user@host:";
        let result = SftpDestination::parse(dest_str).unwrap();
        assert_eq!(result.host, "host");
        assert_eq!(result.user, Some("user".to_string()));
        assert_eq!(result.remote_path, Some("".to_string()));
    }
}

#[cfg(test)]
mod initial_tests {
    #[test]
    fn it_still_works() {
        assert_eq!(1, 1);
    }
}

#[cfg(test)]
mod path_resolution_tests {
    use super::*;

    #[test]
    fn resolve_absolute_path() {
        let current = PathBuf::from("/foo/bar");
        assert_eq!(resolve_sftp_path(&current, "/baz"), PathBuf::from("/baz"));
        assert_eq!(resolve_sftp_path(&current, "/"), PathBuf::from("/"));
    }

    #[test]
    fn resolve_relative_path() {
        let current = PathBuf::from("/foo/bar");
        assert_eq!(resolve_sftp_path(&current, "baz"), PathBuf::from("/foo/bar/baz"));
        assert_eq!(resolve_sftp_path(&current, "baz/qux"), PathBuf::from("/foo/bar/baz/qux"));
    }

    #[test]
    fn resolve_relative_path_with_dot() {
        let current = PathBuf::from("/foo/bar");
        assert_eq!(resolve_sftp_path(&current, "."), PathBuf::from("/foo/bar"));
    }

    #[test]
    fn resolve_relative_path_with_dot_dot() {
        let current = PathBuf::from("/foo/bar");
        assert_eq!(resolve_sftp_path(&current, ".."), PathBuf::from("/foo/bar/.."));
        assert_eq!(resolve_sftp_path(&current, "../baz"), PathBuf::from("/foo/bar/../baz"));
    }

    #[test]
    fn resolve_empty_path() {
        let current = PathBuf::from("/foo/bar");
        assert_eq!(resolve_sftp_path(&current, ""), PathBuf::from("/foo/bar/"));
    }

    #[test]
    fn resolve_from_root_relative() {
        let current = PathBuf::from("/");
        assert_eq!(resolve_sftp_path(&current, "baz"), PathBuf::from("/baz"));
    }
}

#[cfg(test)]
mod cli_parsing_tests {
    use super::*;

    #[test]
    fn parse_cli_destination_only() {
        let args = Cli::try_parse_from(&["my_sftp", "user@host"]).unwrap();
        assert_eq!(args.destination, "user@host");
        assert_eq!(args.port, None);
        assert_eq!(args.identity_file, None);
        assert!(args.batchfile.is_none());
        assert!(args.command_and_args.is_empty());
    }

    #[test]
    fn parse_cli_with_port() {
        let args = Cli::try_parse_from(&["my_sftp", "-P", "2222", "host"]).unwrap();
        assert_eq!(args.destination, "host");
        assert_eq!(args.port, Some(2222));
    }

    #[test]
    fn parse_cli_with_identity_file() {
        let args = Cli::try_parse_from(&["my_sftp", "-i", "/path/to/key", "host"]).unwrap();
        assert_eq!(args.identity_file, Some(PathBuf::from("/path/to/key")));
    }

    #[test]
    fn parse_cli_with_batch_file() {
        let args = Cli::try_parse_from(&["my_sftp", "-b", "batch.txt", "host"]).unwrap();
        assert_eq!(args.batchfile, Some(PathBuf::from("batch.txt")));
    }

    #[test]
    fn parse_cli_with_command() {
        let args = Cli::try_parse_from(&["my_sftp", "host", "ls", "-l"]).unwrap();
        assert_eq!(args.destination, "host");
        assert_eq!(args.command_and_args, vec!["ls".to_string(), "-l".to_string()]);
    }

    #[test]
    fn parse_cli_all_options() {
        let args = Cli::try_parse_from(&[
            "my_sftp",
            "-P", "2022",
            "-i", "mykey",
            "-b", "mybatch",
            "user@server:/path",
            "get", "remote_file"
        ]).unwrap();
        assert_eq!(args.port, Some(2022));
        assert_eq!(args.identity_file, Some(PathBuf::from("mykey")));
        assert_eq!(args.batchfile, Some(PathBuf::from("mybatch")));
        assert_eq!(args.destination, "user@server:/path");
        assert_eq!(args.command_and_args, vec!["get".to_string(), "remote_file".to_string()]);
    }
}

#[cfg(test)]
mod sftp_client_unit_tests {
    use super::*; // For SftpClient, Path, PathBuf, FileStat, SshError, ErrorCode, eq, MockSftpOps (once defined by mock!)
                  // Note: MockSftpOps itself is defined at the top level of this file now.
                  // So `super::MockSftpOps` or just `MockSftpOps` should work here.

    #[test]
    fn test_list_dir_empty_mocked() {
        let mut mock_sftp = MockSftpOps::new(); // Use the name from mock!
        let current_dir = PathBuf::from("/remote/current");

        mock_sftp.expect_readdir()
            .with(eq(current_dir.clone()))
            .times(1)
            .returning(|_| Ok(Vec::new()));

        let client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            current_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );

        assert!(client.list_dir(None).is_ok());
    }

    #[test]
    fn test_list_dir_with_entries_mocked() {
        let mut mock_sftp = MockSftpOps::new();
        let current_dir = PathBuf::from("/remote/current");

        let file_stat_file = FileStat {
            size: Some(100),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(0o100644),
            atime: Some(0),
            mtime: Some(0),
        };
        let file_stat_dir = FileStat {
            size: Some(4096),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(0o040755),
            atime: Some(0),
            mtime: Some(0),
        };

        let entries = vec![
            (PathBuf::from("file1.txt"), file_stat_file.clone()),
            (PathBuf::from("sub_dir"), file_stat_dir.clone()),
        ];

        mock_sftp.expect_readdir()
            .with(eq(current_dir.clone()))
            .times(1)
            .return_once(move |_| Ok(entries));

        let client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            current_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );
        assert!(client.list_dir(None).is_ok());
    }

    #[test]
    fn test_list_dir_error_mocked() {
        let mut mock_sftp = MockSftpOps::new();
        let current_dir = PathBuf::from("/remote/error_path");

        mock_sftp.expect_readdir()
            .with(eq(current_dir.clone()))
            .times(1)
            .returning(|_| Err(SshError::new(ErrorCode::SFTP(4), "Simulated SFTP error")));

        let client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            current_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );

        let result = client.list_dir(None);
        assert!(result.is_err());
        if let Err(e) = result {
            let ssh_error = e.downcast_ref::<SshError>().expect("Error should be an SshError");
            assert_eq!(ssh_error.code(), ErrorCode::SFTP(4));
        }
    }

    #[test]
    fn test_pwd_remote_mocked() {
        let mock_sftp = MockSftpOps::new(); // Expects no calls for pwd
        let current_dir = PathBuf::from("/home/testuser/foo");

        let client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            current_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );

        // pwd_remote prints to stdout.
        client.pwd_remote();
        // No explicit assert here without stdout capture. Test ensures it runs.
    }

    #[test]
    fn test_cd_remote_success() {
        let mut mock_sftp = MockSftpOps::new();
        let initial_dir = PathBuf::from("/home/user");
        let target_dir_str = "projects";
        let resolved_target_dir = initial_dir.join(target_dir_str);
        let canonical_target_dir = PathBuf::from("/home/user/projects_canonical");
        let canonical_target_dir_for_closure = canonical_target_dir.clone(); // Clone for the returning closure

        mock_sftp.expect_realpath()
            .with(eq(resolved_target_dir.clone()))
            .times(1)
            .returning(move |_| Ok(canonical_target_dir_for_closure.clone()));

        let dir_stat = FileStat { perm: Some(0o040755), size: Some(0), uid: Some(0), gid: Some(0), atime: Some(0), mtime: Some(0) };
        mock_sftp.expect_stat()
            .with(eq(canonical_target_dir.clone())) // Original can be cloned here for eq()
            .times(1)
            .returning(move |_| Ok(dir_stat.clone()));

        let mut client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            initial_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );

        assert!(client.cd_remote(target_dir_str).is_ok());
        // SftpClient.current_remote_path is pub, so we can assert it.
        assert_eq!(client.current_remote_path, canonical_target_dir); // Original used for assert
    }

    #[test]
    fn test_cd_remote_realpath_fails() {
        let mut mock_sftp = MockSftpOps::new();
        let initial_dir = PathBuf::from("/home/user");
        let target_dir_str = "nonexistent";
        let resolved_target_dir = initial_dir.join(target_dir_str);

        mock_sftp.expect_realpath()
            .with(eq(resolved_target_dir.clone()))
            .times(1)
            .returning(|_| Err(SshError::new(ErrorCode::SFTP(4), "No such file")));

        mock_sftp.expect_stat().times(0); // Should not be called

        let mut client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            initial_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );
        assert!(client.cd_remote(target_dir_str).is_err());
        assert_eq!(client.current_remote_path, initial_dir); // Path should not change
    }

    #[test]
    fn test_cd_remote_target_is_file() {
        let mut mock_sftp = MockSftpOps::new();
        let initial_dir = PathBuf::from("/home/user");
        let target_file_str = "myfile.txt";
        let resolved_target_file = initial_dir.join(target_file_str);
        let canonical_target_file = PathBuf::from("/home/user/myfile_canonical.txt");
        let canonical_target_file_for_closure = canonical_target_file.clone(); // Clone for the closure

        mock_sftp.expect_realpath()
            .with(eq(resolved_target_file.clone()))
            .times(1)
            .returning(move |_| Ok(canonical_target_file_for_closure.clone()));

        let file_stat = FileStat { perm: Some(0o100644), size: Some(0), uid: Some(0), gid: Some(0), atime: Some(0), mtime: Some(0) };
        mock_sftp.expect_stat()
            .with(eq(canonical_target_file.clone())) // Original can be cloned here for eq
            .times(1)
            .returning(move |_| Ok(file_stat.clone()));

        let mut client = SftpClient::new_for_test(
            Box::new(mock_sftp),
            initial_dir.clone(),
            PathBuf::from("."), // Added current_local_path
            "mockhost".to_string()
        );
        assert!(client.cd_remote(target_file_str).is_err());
        assert_eq!(client.current_remote_path, initial_dir); // Path should not change
    }
}

#[cfg(test)]
mod sftp_completer_tests {
    use super::*; // For MockSftpOps, SftpClient, FileStat, SshError etc.
    use rust_sftp_client::SftpCompleter; // The struct we're testing
    use rustyline::completion::Completer as RustylineCompleter; // Alias to avoid conflict
    use rustyline::Context;
    use rustyline::history::DefaultHistory; // Import DefaultHistory
    use std::rc::Rc;
    use std::cell::RefCell;

    // Helper to create a FileStat for a directory
    fn dir_stat() -> FileStat {
        FileStat { perm: Some(0o040755), size: Some(4096), uid: Some(1000), gid: Some(1000), atime: Some(0), mtime: Some(0) }
    }

    // Helper to create a FileStat for a file
    fn file_stat() -> FileStat {
        FileStat { perm: Some(0o100644), size: Some(1024), uid: Some(1000), gid: Some(1000), atime: Some(0), mtime: Some(0) }
    }

    // Simpler setup: creates client and completer, assumes mock expectations are set beforehand.
    fn create_completer(mock_sftp: MockSftpOps, current_remote_path_str: &str) -> (SftpCompleter, Rc<RefCell<SftpClient>>) {
        let current_remote_path = PathBuf::from(current_remote_path_str);
        let sftp_client = SftpClient::new_for_test( // This is the call to update
            Box::new(mock_sftp),
            current_remote_path,
            PathBuf::from("."), // Default local path for completer tests
            "mockhost".to_string()
        );
        let client_rc = Rc::new(RefCell::new(sftp_client));
        let completer = SftpCompleter::new(client_rc.clone());
        (completer, client_rc)
    }


    fn assert_completions(
        completer: &SftpCompleter,
        line: &str,
        pos: usize,
        expected_start: usize,
        expected_candidates: &[&str],
    ) {
        let history = DefaultHistory::new();
        let ctx = Context::new(&history);
        let (start, candidates) = completer.complete(line, pos, &ctx).unwrap();
        assert_eq!(start, expected_start, "Completion start position mismatch for line: '{}', pos: {}", line, pos);

        let mut sorted_candidates: Vec<String> = candidates.into_iter().collect();
        sorted_candidates.sort();
        let mut sorted_expected: Vec<String> = expected_candidates.iter().map(|s| s.to_string()).collect();
        sorted_expected.sort();

        assert_eq!(sorted_candidates, sorted_expected, "Candidate list mismatch for line: '{}', pos: {}", line, pos);
    }

    #[test]
    fn complete_command_empty_input() {
        let mock = MockSftpOps::new(); // No SFTP calls expected
        let (completer, _client) = create_completer(mock, "/");
        // Let's list them explicitly as per SftpCompleter::new
        let expected = ["ls", "dir", "get", "put", "cd", "pwd", "rm", "mkdir", "rmdir", "help", "?", "exit", "quit", "bye"];
        assert_completions(&completer, "", 0, 0, &expected);
    }

    #[test]
    fn complete_command_partial() {
        let mock = MockSftpOps::new();
        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "l", 1, 0, &["ls"]);
        assert_completions(&completer, "ge", 2, 0, &["get"]);
         assert_completions(&completer, "ex", 2, 0, &["exit"]);
    }

    #[test]
    fn complete_command_full_match_with_space() {
        let mock = MockSftpOps::new();
        let (completer, _client) = create_completer(mock, "/");
        // If "ls" is typed, it should suggest "ls " to allow starting path completion.
        assert_completions(&completer, "ls", 2, 0, &["ls "]);
        assert_completions(&completer, "cd", 2, 0, &["cd "]);
        // If space is already there
        assert_completions(&completer, "ls ", 3, 3, &[]); // No command completion, should be path completion
    }

    #[test]
    fn complete_path_ls_partial() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat() // stat for /
            .with(eq(Path::new("/")))
            .returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("partial_match_file"), file_stat()),
                (PathBuf::from("partial_other_dir"), dir_stat()),
                (PathBuf::from("another_file"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "ls partial_", 11, 3, &[
            "partial_match_file",
            "partial_other_dir/"
        ]);
    }

    #[test]
    fn complete_path_cd_full_dir_name() {
        let mut mock = MockSftpOps::new();
         mock.expect_stat() // stat for /
            .with(eq(Path::new("/")))
            .returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("existing_dir"), dir_stat()),
                (PathBuf::from("other_file"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        // When "cd existing_dir" is typed, and it's a unique match for a dir,
        // rustyline might call complete again AFTER inserting "existing_dir/".
        // Here, we test the state "cd existing_dir" (pos at end of existing_dir)
        // It should offer "existing_dir/" if "existing_dir" is a known entry.
        assert_completions(&completer, "cd existing_dir", 15, 3, &["existing_dir/"]);
    }

    #[test]
    fn complete_path_get_with_spaces() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat() // stat for /
            .with(eq(Path::new("/")))
            .returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("file with spaces.txt"), file_stat()),
                (PathBuf::from("another file"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "get file with spa", 18, 4, &["file with spaces.txt"]);
    }

    #[test]
    fn complete_path_cursor_not_at_end() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat())); // Allow any stat for simplicity
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("file_alpha"), file_stat()),
                (PathBuf::from("file_beta"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        // Line: "ls file_alp remote_stuff_after"
        // Pos: cursor after "file_alp" (position 12)
        assert_completions(&completer, "ls file_alp remote_stuff_after", 12, 3, &["file_alpha"]);
    }

    #[test]
    fn complete_path_empty_remote_dir() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(Vec::new())); // Empty directory

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "ls ", 3, 3, &[]);
    }

    #[test]
    fn complete_path_readdir_fails() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Err(SshError::new(ErrorCode::SFTP(4), "Permission denied")));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "ls ", 3, 3, &[]);
    }

    #[test]
    fn complete_path_absolute_path() {
        let mut mock = MockSftpOps::new();
        // Stat for the base path being listed
        mock.expect_stat()
            .with(eq(Path::new("/usr/"))) // Base dir derived from "/usr/lo"
            .returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/usr/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("local"), dir_stat()),
                (PathBuf::from("lib"), dir_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/home/user"); // Current dir doesn't matter for absolute
        assert_completions(&completer, "ls /usr/lo", 11, 3, &["local/"]);
    }

    #[test]
    fn complete_path_with_dot_dot() {
        let mut mock = MockSftpOps::new();
        // Stat for the resolved path "../d" from "/a/b/c" -> "/a/b/d"
        let base_dir = PathBuf::from("/a/b"); // client.resolve_remote_path("../") from /a/b/c
        mock.expect_stat()
             .with(eq(base_dir.clone())) // for base_dir_to_list
             .returning(move |_| Ok(dir_stat()));

        mock.expect_readdir()
            .with(eq(base_dir.clone())) // for readdir itself
            .returning(|_| Ok(vec![
                (PathBuf::from("dir1"), dir_stat()),
                (PathBuf::from("dir2_other"), dir_stat()),
                (PathBuf::from("file_in_b"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/a/b/c");
        assert_completions(&completer, "ls ../dir", 10, 3, &["dir1/", "dir2_other/"]);
    }

    #[test]
    fn complete_put_command_second_arg() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat())); // For current dir "/"
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("remote_place"), dir_stat()),
                (PathBuf::from("remote_file.txt"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "put localfile.txt remote_", 25, 18, &[
            "remote_place/",
            "remote_file.txt"
        ]);
    }

    #[test]
    fn complete_put_command_after_first_arg_space() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("remote_A"), dir_stat()),
                (PathBuf::from("remote_B"), file_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        // Cursor is at "put localfile.txt |" (pos 18)
        assert_completions(&completer, "put localfile.txt ", 18, 18, &[
            "remote_A/",
            "remote_B"
        ]);
    }

    #[test]
    fn no_remote_completion_for_put_first_arg() {
        let mock = MockSftpOps::new(); // No SFTP calls should be made
        // Expectations for readdir or stat would fail if called.

        let (completer, _client) = create_completer(mock, "/");
        // Trying to complete first arg of put "put loca|"
        assert_completions(&completer, "put loca", 8, 4, &[]); // No remote completions
    }

    #[test]
    fn complete_path_multiple_spaces_between_args() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![(PathBuf::from("spaced_out_file"), file_stat())]));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "ls    spaced_out", 17, 6, &["spaced_out_file"]);
    }

    #[test]
    fn complete_path_leading_spaces_before_command() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![(PathBuf::from("lead_file"), file_stat())]));

        let (completer, _client) = create_completer(mock, "/");
        assert_completions(&completer, "  ls lead_", 11, 5, &["lead_file"]);
    }
     #[test]
    fn complete_path_trailing_spaces_after_partial_arg() {
        let mut mock = MockSftpOps::new();
        mock.expect_stat().returning(|_| Ok(dir_stat()));
        mock.expect_readdir()
            .with(eq(Path::new("/")))
            .returning(|_| Ok(vec![
                (PathBuf::from("trail_file"), file_stat()),
                (PathBuf::from("trail_dir"), dir_stat()),
            ]));

        let (completer, _client) = create_completer(mock, "/");
        // This case means "ls trail |" (cursor after space)
        // The `determine_completion_context` should identify this as completing a *new, empty* argument.
        // However, if the intent is to complete "trail" itself, the cursor should be `ls trail|`
        // If line is "ls trail  " and pos is 10 (after spaces), it means we are starting a new (3rd) argument.
        // The current completer logic, if `determine_completion_context` sets `text=""` and `start_pos=pos`,
        // would try to list entries in "/" matching an empty prefix.
        assert_completions(&completer, "ls trail  ", 10, 10, &[
            "trail_file",
            "trail_dir/"
        ]);
    }
}
