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
mod local_command_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir; // Changed from TempDir to tempdir for function usage

    // Helper function to create an SftpClient for local tests
    fn create_test_client(initial_local_path: PathBuf) -> SftpClient {
        let mock_sftp = MockSftpOps::new(); // No remote operations expected for lls/lcd
        SftpClient::new_for_test(
            Box::new(mock_sftp),
            PathBuf::from("/mock/remote"), // Mock remote path, not used by lls/lcd
            initial_local_path,
            "localtest_mockhost".to_string(),
        )
    }

    #[test]
    fn test_lcd_to_subdir_relative() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let subdir = base_temp_dir.path().join("subdir1");
        fs::create_dir(&subdir).expect("Failed to create subdir");

        let mut client = create_test_client(base_temp_dir.path().to_path_buf());

        let result = client.lcd("subdir1");
        assert!(result.is_ok(), "lcd to subdir1 failed: {:?}", result.err());

        let expected_path = fs::canonicalize(&subdir).expect("Failed to canonicalize subdir");
        assert_eq!(client.current_local_path, expected_path);
    }

    #[test]
    fn test_lcd_to_subdir_absolute() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let subdir = base_temp_dir.path().join("subdir_abs");
        fs::create_dir(&subdir).expect("Failed to create subdir_abs");
        let subdir_abs_path_str = subdir.to_str().unwrap();

        // Start client in a different directory to ensure absolute path works
        let other_temp_dir = tempdir().expect("Failed to create other temp dir");
        let mut client = create_test_client(other_temp_dir.path().to_path_buf());

        let result = client.lcd(subdir_abs_path_str);
        assert!(result.is_ok(), "lcd to absolute path failed: {:?}", result.err());

        let expected_path = fs::canonicalize(&subdir).expect("Failed to canonicalize subdir_abs");
        assert_eq!(client.current_local_path, expected_path);
    }

    #[test]
    fn test_lcd_to_parent_dir() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let subdir = base_temp_dir.path().join("subdir_for_parent_test");
        fs::create_dir(&subdir).expect("Failed to create subdir_for_parent_test");

        let mut client = create_test_client(subdir.clone()); // Start in subdir

        let result = client.lcd("..");
        assert!(result.is_ok(), "lcd to parent failed: {:?}", result.err());

        let expected_path = fs::canonicalize(base_temp_dir.path()).expect("Failed to canonicalize base_temp_dir");
        assert_eq!(client.current_local_path, expected_path);
    }

    #[test]
    fn test_lcd_non_existent_path() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let initial_path = base_temp_dir.path().to_path_buf();
        let mut client = create_test_client(initial_path.clone());

        let result = client.lcd("non_existent_dir");
        assert!(result.is_err(), "lcd to non_existent_dir should fail");
        assert_eq!(client.current_local_path, initial_path); // Path should not change
    }

    #[test]
    fn test_lcd_to_file() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let file_path = base_temp_dir.path().join("file.txt");
        fs::File::create(&file_path).expect("Failed to create file.txt");

        let initial_path = base_temp_dir.path().to_path_buf();
        let mut client = create_test_client(initial_path.clone());

        let result = client.lcd("file.txt");
        assert!(result.is_err(), "lcd to a file should fail");
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("Not a directory"), "Error message mismatch: {}", err_msg);
        assert_eq!(client.current_local_path, initial_path); // Path should not change
    }

    #[test]
    fn test_lcd_empty_path() {
        let base_temp_dir = tempdir().expect("Failed to create base temp dir");
        let initial_path = base_temp_dir.path().to_path_buf();
        let mut client = create_test_client(initial_path.clone());

        let result = client.lcd(""); // Behavior might depend on std::fs::canonicalize("")
                                      // Typically canonicalize("") fails or refers to current dir.
                                      // Our lcd should probably error if path is empty before canonicalize.
                                      // Based on current lcd impl, canonicalize will fail.
        assert!(result.is_err(), "lcd with empty path should fail");
        assert_eq!(client.current_local_path, initial_path); // Path should not change
    }


    // --- lls Tests ---
    #[test]
    fn test_lls_current_dir_with_content() {
        let temp_dir = tempdir().expect("Failed to create temp_dir for lls");
        fs::File::create(temp_dir.path().join("file_a.txt")).unwrap();
        fs::File::create(temp_dir.path().join("file_b.txt")).unwrap();
        fs::create_dir(temp_dir.path().join("sub_dir_c")).unwrap();

        let client = create_test_client(temp_dir.path().to_path_buf());
        // As per subtask, if output capture is hard, just test Ok/Err
        // This test assumes lls prints to stdout. We check if it runs without error.
        let result = client.lls(None);
        assert!(result.is_ok(), "lls failed for current directory: {:?}", result.err());
    }

    #[test]
    fn test_lls_relative_path_subdir() {
        let base_dir = tempdir().expect("Failed to create base_dir for lls relative");
        let sub_dir = base_dir.path().join("my_subdir");
        fs::create_dir(&sub_dir).unwrap();
        fs::File::create(sub_dir.join("file_in_sub.txt")).unwrap();

        let client = create_test_client(base_dir.path().to_path_buf());
        let result = client.lls(Some("my_subdir"));
        assert!(result.is_ok(), "lls failed for relative subdir: {:?}", result.err());
    }

    #[test]
    fn test_lls_absolute_path_subdir() {
        let base_dir = tempdir().expect("Failed to create base_dir for lls absolute");
        let sub_dir = base_dir.path().join("another_subdir");
        fs::create_dir(&sub_dir).unwrap();
        fs::File::create(sub_dir.join("abs_file.txt")).unwrap();
        let sub_dir_abs_path_str = sub_dir.to_str().unwrap();

        // Start client in a different directory
        let other_dir = tempdir().expect("Failed to create other_dir for lls absolute");
        let client = create_test_client(other_dir.path().to_path_buf());

        let result = client.lls(Some(sub_dir_abs_path_str));
        assert!(result.is_ok(), "lls failed for absolute subdir path: {:?}", result.err());
    }

    #[test]
    fn test_lls_empty_directory() {
        let temp_dir = tempdir().expect("Failed to create empty_dir for lls");
        let client = create_test_client(temp_dir.path().to_path_buf());
        let result = client.lls(None);
        assert!(result.is_ok(), "lls failed for empty directory: {:?}", result.err());
        // If we could capture output, we'd check for "(empty directory)"
    }

    #[test]
    fn test_lls_non_existent_path() {
        let temp_dir = tempdir().expect("Failed to create temp_dir for lls non-existent");
        let client = create_test_client(temp_dir.path().to_path_buf());
        let result = client.lls(Some("no_such_dir_here"));
        assert!(result.is_err(), "lls should fail for non-existent path");
    }

    #[test]
    fn test_lls_on_file_path() {
        let temp_dir = tempdir().expect("Failed to create temp_dir for lls on file");
        let file_path = temp_dir.path().join("i_am_a_file.txt");
        fs::File::create(&file_path).unwrap();

        let client = create_test_client(temp_dir.path().to_path_buf());
        let result = client.lls(Some("i_am_a_file.txt"));
        assert!(result.is_err(), "lls should fail when path is a file");
         let err_msg = result.err().unwrap().to_string();
        // The error comes from std::fs::read_dir, which varies by OS,
        // but it should indicate it's not a directory or similar.
        // For example, on Linux: "Not a directory (os error 20)"
        // On Windows: "The directory name is invalid. (os error 267)"
        // For now, checking it's an error is sufficient given the constraints.
        assert!(err_msg.contains("Could not read directory"), "Error message mismatch: {}", err_msg);
    }
}
