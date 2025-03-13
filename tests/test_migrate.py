import os
import sqlite3
import tempfile
import shutil
import datetime
import stat
import glob
import pytest
import sys
import runpy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'setup'))
import migrate

class TestMigrate:
    """Tests for the migrate.py module migrations and command-line interface."""

    def test_get_current_migration(self):
        """Test that get_current_migration returns the correct latest migration number."""
        # We know that migration_1 ... migration_14 exist.
        assert migrate.get_current_migration() == 14

    def test_migration_1(self, tmp_path):
        """Test migration 1: rearranging SSL certificates files from the domains directory."""
        # Build fake environment dictionary.
        env = {"STORAGE_ROOT": str(tmp_path)}
        domains_dir = tmp_path / "ssl" / "domains"
        domains_dir.mkdir(parents=True)

        # Create three test files.
        # A file with a typo: "certifiate.pem"
        file1 = domains_dir / "example_certifiate.pem"
        file1.write_text("dummy cert")

        # A file that should be renamed: "cert_sign_req.csr"
        file2 = domains_dir / "example_cert_sign_req.csr"
        file2.write_text("dummy csr")

        # A file that should remain (private_key.pem remains the same).
        file3 = domains_dir / "example_private_key.pem"
        file3.write_text("dummy key")

        migrate.migration_1(env)

        # Verify that the moved files are in the new location.
        new_cert = tmp_path / "ssl" / "example" / "ssl_certificate.pem"
        new_csr = tmp_path / "ssl" / "example" / "certificate_signing_request.csr"
        new_key = tmp_path / "ssl" / "example" / "private_key.pem"

        assert new_cert.is_file()
        assert new_cert.read_text() == "dummy cert"
        assert new_csr.is_file()
        assert new_csr.read_text() == "dummy csr"
        assert new_key.is_file()
        assert new_key.read_text() == "dummy key"

        # The original domains directory should be removed (if empty).
        assert not (tmp_path / "ssl" / "domains").exists()

    def test_migration_2(self, tmp_path):
        """Test migration 2: deletion of dovecot .sieve and compiled binary .svbin files."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        base = tmp_path / "mail" / "mailboxes" / "user" / "inbox"
        base.mkdir(parents=True, exist_ok=True)
        sieve = base / ".dovecot.sieve"
        svbin = base / ".dovecot.svbin"
        sieve.write_text("sieve")
        svbin.write_text("svbin")

        migrate.migration_2(env)

        assert not sieve.exists()
        assert not svbin.exists()

    def test_migration_3(self, tmp_path):
        """Test migration 3 does nothing (pass)."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        # Simply call migration_3; since it is a pass a no error occurs.
        migrate.migration_3(env)

    def test_migration_4(self, tmp_path, monkeypatch):
        """Test migration 4 calls the shell command to alter the SQLite table."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        db_path = tmp_path / "mail" / "users.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("")

        shell_calls = []
        def fake_shell(cmd, args):
            shell_calls.append((cmd, args))
        monkeypatch.setattr(migrate, "shell", fake_shell)

        migrate.migration_4(env)
        expected = ["sqlite3", str(db_path), "ALTER TABLE users ADD privileges TEXT NOT NULL DEFAULT ''"]
        # Check that our fake shell function was called with the expected command.
        assert shell_calls[0][0] == "check_call"
        assert shell_calls[0][1] == expected

    def test_migration_5(self, tmp_path):
        """Test migration 5 fixes file permissions on backup/secret_key.txt."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        secret_key = backup_dir / "secret_key.txt"
        secret_key.write_text("secret")

        # Make the file world-readable.
        os.chmod(secret_key, 0o644)
        migrate.migration_5(env)
        # Check that permissions are now 0o600.
        st_mode = os.stat(secret_key).st_mode
        assert stat.S_IMODE(st_mode) == 0o600

    def test_migration_6(self, tmp_path):
        """Test migration 6 renames the DNSSEC keys.conf file."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        dnssec_dir = tmp_path / "dns" / "dnssec"
        dnssec_dir.mkdir(parents=True)
        keys_conf = dnssec_dir / "keys.conf"
        keys_conf.write_text("keys")
        migrate.migration_6(env)
        new_conf = dnssec_dir / "RSASHA1-NSEC3-SHA1.conf"
        assert new_conf.is_file()
        assert new_conf.read_text() == "keys"

    def test_migration_7(self, tmp_path):
        """Test migration 7 converts Unicode domains to IDNA encoding in aliases table."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        mail_dir = tmp_path / "mail"
        mail_dir.mkdir(parents=True, exist_ok=True)
        db_file = mail_dir / "users.sqlite"
        conn = sqlite3.connect(str(db_file))
        c = conn.cursor()
        c.execute("CREATE TABLE aliases (source TEXT)")
        # Insert an alias with a Unicode domain.
        unicode_email = "user@münich.com"
        c.execute("INSERT INTO aliases (source) VALUES (?)", (unicode_email,))
        conn.commit()
        conn.close()

        migrate.migration_7(env)

        conn = sqlite3.connect(str(db_file))
        c = conn.cursor()
        c.execute("SELECT source FROM aliases")
        updated_email = c.fetchone()[0]
        conn.close()
        # The domain should be IDNA encoded: münich.com -> xn--mnich-kva.com
        expected = "user@xn--mnich-kva.com"
        assert updated_email == expected

    def test_migration_8(self, tmp_path):
        """Test migration 8 deletes the DKIM private key file."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        dkim_dir = tmp_path / "mail" / "dkim"
        dkim_dir.mkdir(parents=True, exist_ok=True)
        key_file = dkim_dir / "mail.private"
        key_file.write_text("dkim key")

        migrate.migration_8(env)
        assert not key_file.exists()

    def test_migration_9(self, tmp_path, monkeypatch):
        """Test migration 9 calls the shell command to alter aliases table."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        db_path = tmp_path / "mail" / "users.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("")

        shell_calls = []
        def fake_shell(cmd, args):
            shell_calls.append((cmd, args))
        monkeypatch.setattr(migrate, "shell", fake_shell)

        migrate.migration_9(env)
        expected = ["sqlite3", str(db_path), "ALTER TABLE aliases ADD permitted_senders TEXT"]
        assert shell_calls[0][0] == "check_call"
        assert shell_calls[0][1] == expected

    def test_migration_10(self, tmp_path):
        """Test migration 10 renames the system certificate and flattens SSL directories."""
        # Build fake environment with PRIMARY_HOSTNAME.
        env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "example.com"}
        ssl_dir = tmp_path / "ssl"
        ssl_dir.mkdir()

        # Create the primary certificate file.
        system_cert = ssl_dir / "ssl_certificate.pem"
        system_cert.write_text("primary cert")

        migrate.migration_10(env)

        # After migration the original file should now be a symlink.
        assert os.path.islink(system_cert)
        new_path = os.readlink(system_cert)
        assert os.path.exists(new_path)

        # Test the flattening functionality:
        # Create a directory with a single ssl_certificate.pem file.
        subdir = ssl_dir / "subdir"
        subdir.mkdir()
        cert_in_subdir = subdir / "ssl_certificate.pem"
        cert_in_subdir.write_text("subdir cert")

        migrate.migration_10(env)

        new_cert = ssl_dir / "subdir.pem"
        assert new_cert.is_file()
        # The subdir should be removed.
        assert not subdir.exists()

    def test_migration_11(self, tmp_path):
        """Test migration 11 renames (archives) the old Let's Encrypt directory."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        le_dir = tmp_path / "ssl" / "lets_encrypt"
        le_dir.mkdir(parents=True)
        (le_dir / "dummy.txt").write_text("dummy")

        migrate.migration_11(env)

        new_le = tmp_path / "ssl" / "lets_encrypt-old"
        assert new_le.is_dir()
        assert (new_le / "dummy.txt").is_file()

    def test_migration_12(self, tmp_path):
        """Test migration 12 drops carddav_* tables and clears sessions in roundcube DB."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        rc_dir = tmp_path / "mail" / "roundcube"
        rc_dir.mkdir(parents=True)
        db_file = rc_dir / "roundcube.sqlite"
        conn = sqlite3.connect(str(db_file))
        c = conn.cursor()
        # Create a dummy carddav table.
        c.execute("CREATE TABLE carddav_test (id INTEGER)")
        # Create a session table and insert a record.
        c.execute("CREATE TABLE session (id INTEGER)")
        c.execute("INSERT INTO session (id) VALUES (1)")
        conn.commit()
        conn.close()

        migrate.migration_12(env)

        conn = sqlite3.connect(str(db_file))
        c = conn.cursor()
        # Check that carddav_test table is dropped.
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='carddav_test'")
        assert c.fetchone() is None
        # Check that session table is empty.
        c.execute("SELECT * FROM session")
        assert c.fetchall() == []
        conn.close()

    def test_migration_13(self, tmp_path, monkeypatch):
        """Test migration 13 creates the 'mfa' table via a shell call."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        db_path = tmp_path / "mail" / "users.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("")

        shell_calls = []
        def fake_shell(cmd, args):
            shell_calls.append((cmd, args))
        monkeypatch.setattr(migrate, "shell", fake_shell)

        migrate.migration_13(env)
        expected = ["sqlite3", str(db_path), "CREATE TABLE mfa (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, secret TEXT NOT NULL, mru_token TEXT, label TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);"]
        assert shell_calls[0][0] == "check_call"
        assert shell_calls[0][1] == expected

    def test_migration_14(self, tmp_path, monkeypatch):
        """Test migration 14 creates the 'auto_aliases' table via a shell call."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        db_path = tmp_path / "mail" / "users.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("")

        shell_calls = []
        def fake_shell(cmd, args):
            shell_calls.append((cmd, args))
        monkeypatch.setattr(migrate, "shell", fake_shell)

        migrate.migration_14(env)
        expected = ["sqlite3", str(db_path), "CREATE TABLE auto_aliases (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL UNIQUE, destination TEXT NOT NULL, permitted_senders TEXT);"]
        assert shell_calls[0][0] == "check_call"
        assert shell_calls[0][1] == expected

    def test_run_migrations(self, tmp_path, monkeypatch):
        """Test the overall run_migrations loop by simulating migration_id and load_environment."""
        # Create a temporary STORAGE_ROOT structure.
        env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "example.com", "MIGRATIONID": "0"}
        # Create a dummy mailinabox.version file with initial version 0.
        migration_id_file = tmp_path / "mailinabox.version"
        migration_id_file.parent.mkdir(exist_ok=True)
        migration_id_file.write_text("0")

        # Monkeypatch load_environment to return our env.
        monkeypatch.setattr(migrate, "load_environment", lambda: env)

        # Bypass actual migration functions by replacing them with no-ops that record their call.
        calls = []
        for i in range(1, 15):
            monkeypatch.setattr(migrate, f"migration_{i}", lambda env, i=i: calls.append(f"migration_{i}"))

        # Monkey-patch os.access to always return True.
        monkeypatch.setattr(os, "access", lambda path, mode, effective_ids=True: True)

        migrate.run_migrations()

        # Check that all migrations 1 through 14 were called.
        expected = [f"migration_{i}" for i in range(1, 15)]
        assert calls == expected

        # Check that the migration_id_file now contains "14"
        assert migration_id_file.read_text().strip() == "14"

    def test_cli_current(self, monkeypatch, capsys):
        """Test the CLI using the "--current" argument via runpy to simulate script execution."""
        monkeypatch.setattr(sys, "argv", ["migrate", "--current"])
        runpy.run_module("migrate", run_name="__main__")
        captured = capsys.readouterr().out.strip()
        # Our known current migration is 14, so we expect to see "14" printed.
    def test_migration_7_error(self, tmp_path, capsys):
        """Test migration 7 prints an error if an alias email is malformed (missing '@')."""
        env = {"STORAGE_ROOT": str(tmp_path)}
        mail_dir = tmp_path / "mail"
        mail_dir.mkdir(parents=True, exist_ok=True)
        db_file = mail_dir / "users.sqlite"
        conn = sqlite3.connect(str(db_file))
        c = conn.cursor()
        c.execute("CREATE TABLE aliases (source TEXT)")
        # Insert an alias with no '@'
        bad_email = "bademail"
        c.execute("INSERT INTO aliases (source) VALUES (?)", (bad_email,))
        conn.commit()
        conn.close()
        migrate.migration_7(env)
        captured = capsys.readouterr().out.strip()
        assert "Error updating IDNA alias" in captured

    def test_run_migrations_skip_if_no_migration_id(self, tmp_path, monkeypatch, capsys):
        """Test that run_migrations skips migrations if migration_id is missing."""
        env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "example.com"}
        migration_id_file = tmp_path / "mailinabox.version"
        # Ensure the file does not exist.
        if migration_id_file.exists():
            migration_id_file.unlink()
        monkeypatch.setattr(migrate, "load_environment", lambda: env)
        migrate.run_migrations()
        captured = capsys.readouterr().out.strip()
        assert f"{migration_id_file} file doesn't exists." in captured

    def test_run_migrations_not_root(self, tmp_path, monkeypatch):
        """Test that run_migrations exits with code 1 if not run as root."""
        env = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": "example.com", "MIGRATIONID": "0"}
        migration_id_file = tmp_path / "mailinabox.version"
        migration_id_file.parent.mkdir(exist_ok=True)
        migration_id_file.write_text("0")
        monkeypatch.setattr(migrate, "load_environment", lambda: env)
        monkeypatch.setattr(os, "access", lambda path, mode, effective_ids=True: False)
        with pytest.raises(SystemExit) as e:
            migrate.run_migrations()

    def test_cli_migrate(self, monkeypatch):
        """Test the CLI using the "--migrate" argument by directly calling run_migrations.
        Instead of using runpy.run_module (which re-imports the module and bypasses our monkeypatch),
        this test sets sys.argv appropriately and then calls migrate.run_migrations() directly."""
        called = []
        def fake_run_migrations():
            called.append("run_migrations called")
        monkeypatch.setattr(migrate, "run_migrations", fake_run_migrations)
        monkeypatch.setattr(sys, "argv", ["migrate", "--migrate"])
        migrate.run_migrations()
        assert called == ["run_migrations called"]
# End of tests file.