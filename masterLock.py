import argparse
import base64
import ctypes
import getpass
import hashlib
import hmac
import json
import os
import queue
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    HAS_TK = True
except ImportError:
    HAS_TK = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

APP_TITLE = "VaultLock — Master Locker & One-Click .exe Generator"
MAGIC_AES = b"VLOCK2\x00\x01"
PBKDF2_ITERS = 200_000
NO_WINDOW = 0x08000000 if os.name == "nt" else 0
FILE_ATTRIBUTE_NORMAL = 0x80


# Native C# source compiled via Windows' built-in .NET csc.exe into a ~16 KB standalone toggle .exe
TOGGLE_EXE_CS_TEMPLATE = r"""
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace VaultLockToggle {
    static class Program {
        const string TARGET_NAME = "__TARGET_NAME__";
        const int ITERATIONS = 200000;

        [STAThread]
        static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetPath = Path.Combine(baseDir, TARGET_NAME);
            string keyPath = Path.Combine(baseDir, TARGET_NAME + ".vlock");

            if (!File.Exists(keyPath)) {
                MessageBox.Show(
                    "Lock key not found:\n" + keyPath + "\n\nUse Master VaultLock.exe to set up a lock first.",
                    "VaultLock",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
                return;
            }

            if (!Directory.Exists(targetPath) && !File.Exists(targetPath)) {
                MessageBox.Show(
                    "Protected item not found:\n" + targetPath,
                    "VaultLock",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return;
            }

            try {
                File.SetAttributes(keyPath, FileAttributes.Normal);
            } catch { }

            string json = File.ReadAllText(keyPath, Encoding.UTF8);
            bool isLocked = ParseBool(json, "locked", true);
            string saltB64 = ParseString(json, "salt");
            string hashB64 = ParseString(json, "hash");

            if (string.IsNullOrEmpty(saltB64) || string.IsNullOrEmpty(hashB64)) {
                MessageBox.Show("Invalid .vlock metadata. Repair via Master VaultLock.exe.", "VaultLock", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (!isLocked) {
                // Currently unlocked -> One-click instant lock!
                bool isDir = Directory.Exists(targetPath);
                string perm = isDir ? "(OI)(CI)(F)" : "(F)";
                int rc = RunIcacls("\"" + targetPath + "\" /deny *S-1-1-0:" + perm + " /C /Q");
                if (rc != 0) {
                    MessageBox.Show("Failed to lock item (Windows denied ACL update).", "VaultLock Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                UpdateLockedFlag(keyPath, json, true);
                ShowAutoToast("Locked: " + TARGET_NAME, "Double-click this .exe again and enter your password to unlock.");
            } else {
                // Currently locked -> Prompt for password to unlock!
                using (var dlg = new UnlockPromptForm(TARGET_NAME, targetPath, keyPath, json, saltB64, hashB64)) {
                    Application.Run(dlg);
                }
            }
        }

        static string ParseString(string json, string key) {
            var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"([^\"]*)\"");
            return m.Success ? m.Groups[1].Value : "";
        }

        static bool ParseBool(string json, string key, bool fallback) {
            var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase);
            if (!m.Success) return fallback;
            return m.Groups[1].Value.ToLowerInvariant() == "true";
        }

        static void UpdateLockedFlag(string keyPath, string json, bool lockedVal) {
            string valStr = lockedVal ? "true" : "false";
            string updated;
            if (Regex.IsMatch(json, "\"locked\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase)) {
                updated = Regex.Replace(json, "(\"locked\"\\s*:\\s*)(true|false)", "$1" + valStr, RegexOptions.IgnoreCase);
            } else {
                int idx = json.LastIndexOf('}');
                updated = json.Substring(0, idx).TrimEnd() + ",\n  \"locked\": " + valStr + "\n}\n";
            }
            try { File.SetAttributes(keyPath, FileAttributes.Normal); } catch { }
            File.WriteAllText(keyPath, updated, Encoding.UTF8);
        }

        static int RunIcacls(string args) {
            var psi = new ProcessStartInfo("icacls", args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (var p = Process.Start(psi)) {
                p.StandardInput.Close();
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit(45000);
                return p.ExitCode;
            }
        }

        static byte[] Pbkdf2Sha256(string password, byte[] salt, int iterations, int dkLen) {
            byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
            using (var hmac = new HMACSHA256(pwdBytes)) {
                int hLen = 32;
                int l = (int)Math.Ceiling((double)dkLen / hLen);
                byte[] dk = new byte[l * hLen];
                byte[] saltBlock = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
                for (int i = 1; i <= l; i++) {
                    saltBlock[salt.Length] = (byte)(i >> 24);
                    saltBlock[salt.Length + 1] = (byte)(i >> 16);
                    saltBlock[salt.Length + 2] = (byte)(i >> 8);
                    saltBlock[salt.Length + 3] = (byte)(i);
                    byte[] u = hmac.ComputeHash(saltBlock);
                    byte[] t = (byte[])u.Clone();
                    for (int c = 2; c <= iterations; c++) {
                        u = hmac.ComputeHash(u);
                        for (int j = 0; j < hLen; j++) t[j] ^= u[j];
                    }
                    Buffer.BlockCopy(t, 0, dk, (i - 1) * hLen, hLen);
                }
                byte[] result = new byte[dkLen];
                Buffer.BlockCopy(dk, 0, result, 0, dkLen);
                return result;
            }
        }

        static bool FixedTimeEquals(byte[] a, byte[] b) {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        static void ShowAutoToast(string title, string body) {
            Form f = new Form();
            f.Text = "VaultLock";
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.StartPosition = FormStartPosition.CenterScreen;
            f.Size = new Size(390, 145);
            f.MaximizeBox = false;
            f.MinimizeBox = false;
            f.TopMost = true;
            f.BackColor = Color.FromArgb(15, 23, 42);
            f.ForeColor = Color.White;

            Label lbl1 = new Label();
            lbl1.Text = title;
            lbl1.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
            lbl1.ForeColor = Color.FromArgb(52, 211, 153);
            lbl1.Location = new Point(20, 18);
            lbl1.AutoSize = true;

            Label lbl2 = new Label();
            lbl2.Text = body;
            lbl2.Font = new Font("Segoe UI", 9F);
            lbl2.ForeColor = Color.FromArgb(203, 213, 225);
            lbl2.Location = new Point(20, 48);
            lbl2.Size = new Size(340, 40);

            f.Controls.Add(lbl1);
            f.Controls.Add(lbl2);

            Timer t = new Timer();
            t.Interval = 1400;
            t.Tick += delegate { t.Stop(); f.Close(); };
            f.Shown += delegate { t.Start(); };
            f.Click += delegate { f.Close(); };
            lbl1.Click += delegate { f.Close(); };
            lbl2.Click += delegate { f.Close(); };
            Application.Run(f);
        }

        class UnlockPromptForm : Form {
            string targetName, targetPath, keyPath, json, saltB64, hashB64;
            TextBox txtPwd;
            CheckBox chkShow, chkOpen;
            Label lblErr;

            public UnlockPromptForm(string targetName, string targetPath, string keyPath, string json, string saltB64, string hashB64) {
                this.targetName = targetName;
                this.targetPath = targetPath;
                this.keyPath = keyPath;
                this.json = json;
                this.saltB64 = saltB64;
                this.hashB64 = hashB64;

                this.Text = "Unlock — " + targetName;
                this.FormBorderStyle = FormBorderStyle.FixedDialog;
                this.StartPosition = FormStartPosition.CenterScreen;
                this.Size = new Size(420, 245);
                this.MaximizeBox = false;
                this.MinimizeBox = false;
                this.TopMost = true;
                this.BackColor = Color.FromArgb(15, 23, 42);
                this.ForeColor = Color.White;

                Label lblTitle = new Label();
                lblTitle.Text = "Protected Item: " + targetName;
                lblTitle.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
                lblTitle.Location = new Point(22, 18);
                lblTitle.AutoSize = true;

                Label lblSub = new Label();
                lblSub.Text = "Enter password to unlock (click this .exe again later to re-lock):";
                lblSub.Font = new Font("Segoe UI", 8.5F);
                lblSub.ForeColor = Color.FromArgb(148, 163, 184);
                lblSub.Location = new Point(22, 44);
                lblSub.AutoSize = true;

                txtPwd = new TextBox();
                txtPwd.Font = new Font("Segoe UI", 11F);
                txtPwd.UseSystemPasswordChar = true;
                txtPwd.BackColor = Color.FromArgb(30, 41, 59);
                txtPwd.ForeColor = Color.White;
                txtPwd.BorderStyle = BorderStyle.FixedSingle;
                txtPwd.Location = new Point(22, 70);
                txtPwd.Size = new Size(360, 28);

                chkShow = new CheckBox();
                chkShow.Text = "Show Password";
                chkShow.Font = new Font("Segoe UI", 8.5F);
                chkShow.ForeColor = Color.FromArgb(148, 163, 184);
                chkShow.Location = new Point(22, 106);
                chkShow.AutoSize = true;
                chkShow.CheckedChanged += delegate { txtPwd.UseSystemPasswordChar = !chkShow.Checked; };

                chkOpen = new CheckBox();
                chkOpen.Text = "Open after unlock";
                chkOpen.Checked = true;
                chkOpen.Font = new Font("Segoe UI", 8.5F);
                chkOpen.ForeColor = Color.FromArgb(148, 163, 184);
                chkOpen.Location = new Point(235, 106);
                chkOpen.AutoSize = true;

                lblErr = new Label();
                lblErr.Text = "";
                lblErr.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
                lblErr.ForeColor = Color.FromArgb(248, 113, 113);
                lblErr.Location = new Point(22, 132);
                lblErr.AutoSize = true;

                Button btnUnlock = new Button();
                btnUnlock.Text = "Unlock Now";
                btnUnlock.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
                btnUnlock.BackColor = Color.FromArgb(16, 185, 129);
                btnUnlock.ForeColor = Color.White;
                btnUnlock.FlatStyle = FlatStyle.Flat;
                btnUnlock.FlatAppearance.BorderSize = 0;
                btnUnlock.Location = new Point(22, 158);
                btnUnlock.Size = new Size(360, 36);
                btnUnlock.Click += delegate { TryUnlock(); };

                this.AcceptButton = btnUnlock;
                this.Controls.Add(lblTitle);
                this.Controls.Add(lblSub);
                this.Controls.Add(txtPwd);
                this.Controls.Add(chkShow);
                this.Controls.Add(chkOpen);
                this.Controls.Add(lblErr);
                this.Controls.Add(btnUnlock);
            }

            void TryUnlock() {
                string pwd = txtPwd.Text;
                if (string.IsNullOrEmpty(pwd)) {
                    lblErr.Text = "Please enter your password.";
                    return;
                }
                byte[] salt = Convert.FromBase64String(saltB64);
                byte[] expected = Convert.FromBase64String(hashB64);
                byte[] actual = Pbkdf2Sha256(pwd, salt, ITERATIONS, 32);
                if (!FixedTimeEquals(actual, expected)) {
                    lblErr.Text = "Incorrect password! Try again.";
                    txtPwd.SelectAll();
                    txtPwd.Focus();
                    return;
                }

                try { File.SetAttributes(targetPath, FileAttributes.Normal); } catch { }
                bool isDir = Directory.Exists(targetPath);
                if (isDir) {
                    RunIcacls("\"" + targetPath + "\" /remove:d *S-1-1-0 /T /C /Q");
                    RunIcacls("\"" + targetPath + "\" /reset /T /C /Q");
                } else {
                    RunIcacls("\"" + targetPath + "\" /remove:d *S-1-1-0 /C /Q");
                    RunIcacls("\"" + targetPath + "\" /reset /C /Q");
                }

                UpdateLockedFlag(keyPath, json, false);

                if (chkOpen.Checked) {
                    try {
                        Process.Start(new ProcessStartInfo(targetPath) { UseShellExecute = true });
                    } catch { }
                }
                this.Close();
            }
        }
    }
}
"""


def _run_silent(cmd: list[str], timeout: int = 20) -> int:
    try:
        res = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=NO_WINDOW,
        )
        return res.returncode
    except Exception:
        return -1


def _clear_win_attributes(path: Path) -> None:
    if os.name != "nt" or not path.exists():
        return
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def _unlock_win_acl(path: Path, recursive: bool = True) -> None:
    if os.name != "nt" or not path.exists():
        return
    _clear_win_attributes(path)
    if recursive and path.is_dir():
        _run_silent(["icacls", str(path), "/remove:d", "*S-1-1-0", "/T", "/C", "/Q"], timeout=60)
        _run_silent(["icacls", str(path), "/reset", "/T", "/C", "/Q"], timeout=60)
        _run_silent(["attrib", "-r", "-s", "-h", str(path / "*"), "/S", "/D"], timeout=60)
    else:
        _run_silent(["icacls", str(path), "/remove:d", "*S-1-1-0", "/C", "/Q"], timeout=15)
        _run_silent(["icacls", str(path), "/reset", "/C", "/Q"], timeout=15)


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERS,
        dklen=32,
    )


def _find_windows_csc() -> Path | None:
    if os.name != "nt":
        return None
    win_dir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        win_dir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
        win_dir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def create_one_click_toggle_exe(target: Path) -> Path:
    """Builds '<TargetName> Lock.exe' right beside target using Windows' built-in csc.exe (or self-clone fallback)."""
    toggle_exe = target.with_name(f"{target.name} Lock.exe")
    _clear_win_attributes(toggle_exe)
    if toggle_exe.exists():
        toggle_exe.unlink(missing_ok=True)

    csc = _find_windows_csc()
    if csc:
        escaped_name = target.name.replace("\\", "\\\\").replace('"', '\\"')
        cs_code = TOGGLE_EXE_CS_TEMPLATE.replace("__TARGET_NAME__", escaped_name)
        tmp_dir = Path(tempfile.mkdtemp(prefix="vlock_cs_"))
        try:
            cs_file = tmp_dir / "ToggleLocker.cs"
            cs_file.write_text(cs_code, encoding="utf-8")
            cmd = [
                str(csc),
                "/nologo",
                "/optimize+",
                "/target:winexe",
                "/r:System.dll",
                "/r:System.Drawing.dll",
                "/r:System.Windows.Forms.dll",
                f"/out:{toggle_exe}",
                str(cs_file),
            ]
            rc = _run_silent(cmd, timeout=30)
            if rc == 0 and toggle_exe.exists():
                return toggle_exe
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # Fallback if csc.exe is unavailable: clone frozen VaultLock.exe as '<Name> Lock.exe'
    if getattr(sys, "frozen", False):
        shutil.copy2(sys.executable, toggle_exe)
        return toggle_exe

    raise RuntimeError("Could not locate Windows .NET csc.exe or frozen VaultLock.exe to generate toggle .exe.")


def _read_and_verify_key(key_file: Path, password: str) -> dict:
    if not key_file.exists():
        raise FileNotFoundError(f"Lock key not found: {key_file}")

    _clear_win_attributes(key_file)
    if not os.access(key_file, os.R_OK | os.W_OK):
        _unlock_win_acl(key_file, recursive=False)

    try:
        meta = json.loads(key_file.read_text(encoding="utf-8-sig"))
        salt = base64.b64decode(meta["salt"])
        expected_hash = base64.b64decode(meta["hash"])
    except Exception as exc:
        raise ValueError(f"Invalid or corrupted .vlock key file: {exc}") from exc

    if not hmac.compare_digest(_derive_key(password, salt), expected_hash):
        raise ValueError("Incorrect password!")
    return meta


def lock_with_toggle_exe(target: Path, password: str, progress_cb=None) -> tuple[Path, Path]:
    """First-time setup: locks target, writes .vlock key, and generates '<TargetName> Lock.exe'."""
    if not target.exists():
        raise FileNotFoundError(f"Item not found: {target}")
    if target.suffix.lower() == ".vlock" or target.name.endswith(" Lock.exe"):
        raise ValueError("Select your actual file or folder, not a .vlock or Lock.exe file.")

    key_file = target.with_name(target.name + ".vlock")

    if progress_cb:
        progress_cb(20, "Generating password key...")

    salt = secrets.token_bytes(16)
    pwd_hash = _derive_key(password, salt)
    meta = {
        "mode": "instant",
        "name": target.name,
        "is_dir": target.is_dir(),
        "locked": True,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(pwd_hash).decode("ascii"),
    }
    _clear_win_attributes(key_file)
    key_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if progress_cb:
        progress_cb(50, "Creating one-click toggle .exe...")

    toggle_exe = create_one_click_toggle_exe(target)

    if progress_cb:
        progress_cb(80, "Locking folder/file access...")

    if os.name == "nt":
        perm = "(OI)(CI)(F)" if target.is_dir() else "(F)"
        rc = _run_silent(["icacls", str(target), "/deny", f"*S-1-1-0:{perm}", "/C", "/Q"], timeout=30)
        if rc != 0:
            key_file.unlink(missing_ok=True)
            toggle_exe.unlink(missing_ok=True)
            raise RuntimeError("Windows denied permission to lock this item.")
    else:
        os.chmod(target, 0)

    if progress_cb:
        progress_cb(100, "Locked & created one-click .exe!")
    return key_file, toggle_exe


def _resolve_target_and_key(input_path: Path) -> tuple[Path, Path]:
    if input_path.suffix.lower() == ".vlock":
        return input_path.with_suffix(""), input_path
    if input_path.name.endswith(" Lock.exe"):
        base = input_path.with_name(input_path.name[: -len(" Lock.exe")])
        return base, base.with_name(base.name + ".vlock")
    return input_path, input_path.with_name(input_path.name + ".vlock")


def unlock_item(input_path: Path, password: str, keep_toggle_exe: bool = True, progress_cb=None) -> Path:
    target, key_file = _resolve_target_and_key(input_path)

    if progress_cb:
        progress_cb(25, "Verifying password...")

    meta = _read_and_verify_key(key_file, password)

    if progress_cb:
        progress_cb(65, "Unlocking folder/file...")

    if target.exists():
        if os.name == "nt":
            _unlock_win_acl(target, recursive=True)
        else:
            os.chmod(target, 0o755 if target.is_dir() else 0o644)

    if keep_toggle_exe:
        meta["locked"] = False
        _clear_win_attributes(key_file)
        key_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    else:
        _clear_win_attributes(key_file)
        key_file.unlink(missing_ok=True)
        toggle_exe = target.with_name(f"{target.name} Lock.exe")
        _clear_win_attributes(toggle_exe)
        toggle_exe.unlink(missing_ok=True)

    if progress_cb:
        progress_cb(100, "Unlocked successfully!")
    return target


def change_item_password(input_path: Path, old_password: str, new_password: str, progress_cb=None) -> Path:
    target, key_file = _resolve_target_and_key(input_path)

    if progress_cb:
        progress_cb(30, "Verifying current password...")

    meta = _read_and_verify_key(key_file, old_password)

    if progress_cb:
        progress_cb(70, "Updating password...")

    new_salt = secrets.token_bytes(16)
    new_hash = _derive_key(new_password, new_salt)
    meta["salt"] = base64.b64encode(new_salt).decode("ascii")
    meta["hash"] = base64.b64encode(new_hash).decode("ascii")

    _clear_win_attributes(key_file)
    key_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Ensure companion toggle .exe exists and matches
    toggle_exe = target.with_name(f"{target.name} Lock.exe")
    if not toggle_exe.exists() and target.exists():
        create_one_click_toggle_exe(target)

    if progress_cb:
        progress_cb(100, "Password changed successfully!")
    return target


def remove_item_lock(input_path: Path, password: str, progress_cb=None) -> Path:
    """Verifies password, permanently unlocks item, and removes both .vlock key and '<Name> Lock.exe'."""
    if progress_cb:
        progress_cb(20, "Verifying password to remove lock...")
    return unlock_item(input_path, password, keep_toggle_exe=False, progress_cb=progress_cb)


def install_windows_context_menu(exe_override: Path | None = None) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows Right-Click Menu is only available on Windows.")

    import winreg

    if exe_override and exe_override.exists():
        target_exe = str(exe_override.resolve())
        cmd_str = f'"{target_exe}" "%1"'
        icon_str = f'"{target_exe}",0'
    elif getattr(sys, "frozen", False):
        cmd_str = f'"{sys.executable}" "%1"'
        icon_str = f'"{sys.executable}",0'
    else:
        pyw = Path(sys.executable).with_name("pythonw.exe")
        exe = str(pyw if pyw.exists() else sys.executable)
        script = str(Path(__file__).resolve())
        cmd_str = f'"{exe}" "{script}" "%1"'
        icon_str = f'"{exe}",0'

    for base in (r"Software\Classes\*\shell\VaultLock", r"Software\Classes\Directory\shell\VaultLock"):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Manage Lock with VaultLock")
            winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_str)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\command") as ck:
            winreg.SetValueEx(ck, "", 0, winreg.REG_SZ, cmd_str)


def build_master_exe(progress_cb=None) -> Path:
    if getattr(sys, "frozen", False):
        raise RuntimeError("You are already running the standalone VaultLock.exe!")

    script_path = Path(__file__).resolve()
    out_dir = script_path.parent
    exe_path = out_dir / "VaultLock.exe"

    if exe_path.exists():
        try:
            exe_path.unlink()
        except PermissionError as exc:
            raise RuntimeError("Close VaultLock.exe first before rebuilding it!") from exc

    if progress_cb:
        progress_cb(20, "Checking PyInstaller...")
    if _run_silent([sys.executable, "-m", "PyInstaller", "--version"], timeout=15) != 0:
        if progress_cb:
            progress_cb(40, "Installing PyInstaller...")
        if _run_silent([sys.executable, "-m", "pip", "install", "pyinstaller"], timeout=180) != 0:
            raise RuntimeError("Failed to install PyInstaller. Run: pip install pyinstaller")

    if progress_cb:
        progress_cb(65, "Compiling Master VaultLock.exe (takes ~20s)...")
    build_tmp = out_dir / "_vlock_build"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "VaultLock",
        "--distpath",
        str(out_dir),
        "--workpath",
        str(build_tmp),
        "--specpath",
        str(build_tmp),
        str(script_path),
    ]
    rc = _run_silent(cmd, timeout=240)
    shutil.rmtree(build_tmp, ignore_errors=True)

    if rc != 0 or not exe_path.exists():
        raise RuntimeError("PyInstaller build failed. Ensure 'pip install pyinstaller' works in terminal.")

    install_windows_context_menu(exe_override=exe_path)
    if progress_cb:
        progress_cb(100, "Master VaultLock.exe built & registered!")
    return exe_path


class VaultLockMasterApp:
    def __init__(self, initial_path: str | None = None):
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("680x550")
        self.root.resizable(False, False)
        self.root.configure(bg="#0f172a")

        self.ui_queue: queue.Queue = queue.Queue()
        self.mode = tk.StringVar(value="lock")
        self.path_var = tk.StringVar()
        self.pwd_var = tk.StringVar()
        self.new_pwd_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.show_pwd = tk.BooleanVar(value=False)
        self.open_after_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready.")

        self._build_ui()
        self.root.after(40, self._poll_queue)

        if initial_path:
            p = Path(initial_path)
            self.path_var.set(str(p))
            target, key_file = _resolve_target_and_key(p)
            self._switch_tab("unlock" if key_file.exists() else "lock")
            self.ent_pwd.focus_set()
        else:
            self._switch_tab("lock")

    def _poll_queue(self):
        try:
            while True:
                fn = self.ui_queue.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(40, self._poll_queue)

    def _post_ui(self, fn):
        self.ui_queue.put(fn)

    def _build_ui(self):
        bg = "#0f172a"
        card = "#1e293b"
        fg = "#f8fafc"
        muted = "#94a3b8"

        hdr = tk.Frame(self.root, bg=bg)
        hdr.pack(fill="x", padx=24, pady=(18, 12))
        tk.Label(hdr, text="🔒 VaultLock Master", font=("Segoe UI", 19, "bold"), bg=bg, fg=fg).pack(side="left")

        tk.Button(
            hdr,
            text="⚙ Right-Click Menu",
            font=("Segoe UI", 9, "bold"),
            bg="#1e293b",
            fg="#38bdf8",
            activebackground="#334155",
            activeforeground="#38bdf8",
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
            command=self._on_install_menu,
        ).pack(side="right", padx=(8, 0))

        tk.Button(
            hdr,
            text="📦 Build Master .exe",
            font=("Segoe UI", 9, "bold"),
            bg="#065f46",
            fg="#ecfdf5",
            activebackground="#047857",
            activeforeground="#ecfdf5",
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
            command=self._on_build_exe,
        ).pack(side="right")

        # 4 Navigation Tabs
        tabs = tk.Frame(self.root, bg=card)
        tabs.pack(fill="x", padx=24)

        self.tab_buttons = {}
        tab_defs = [
            ("lock", "🔒 Lock Setup"),
            ("unlock", "🔓 Unlock"),
            ("change", "🔑 Change Password"),
            ("remove", "🗑️ Remove Lock"),
        ]
        for key, label in tab_defs:
            btn = tk.Button(
                tabs,
                text=label,
                font=("Segoe UI", 9, "bold"),
                relief="flat",
                pady=10,
                cursor="hand2",
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(side="left", fill="x", expand=True)
            self.tab_buttons[key] = btn

        # Body Card
        body = tk.Frame(self.root, bg=card, padx=22, pady=18)
        body.pack(fill="both", expand=True, padx=24, pady=(10, 10))

        self.lbl_desc = tk.Label(body, text="", font=("Segoe UI", 9), bg=card, fg="#34d399")
        self.lbl_desc.pack(anchor="w", pady=(0, 10))

        tk.Label(body, text="1. Select File, Image, Video, or Folder:", font=("Segoe UI", 10, "bold"), bg=card, fg=fg).pack(anchor="w")
        row1 = tk.Frame(body, bg=card)
        row1.pack(fill="x", pady=(6, 12))
        tk.Entry(row1, textvariable=self.path_var, font=("Segoe UI", 10), bg="#0f172a", fg=fg, insertbackground=fg, relief="flat").pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        tk.Button(row1, text="📄 File", font=("Segoe UI", 9, "bold"), bg="#334155", fg=fg, relief="flat", padx=12, pady=6, cursor="hand2", command=self._browse_file).pack(side="left", padx=(0, 6))
        tk.Button(row1, text="📁 Folder", font=("Segoe UI", 9, "bold"), bg="#334155", fg=fg, relief="flat", padx=12, pady=6, cursor="hand2", command=self._browse_folder).pack(side="left")

        self.lbl_pwd = tk.Label(body, text="2. Set Password (min 4 characters):", font=("Segoe UI", 10, "bold"), bg=card, fg=fg)
        self.lbl_pwd.pack(anchor="w")
        self.ent_pwd = tk.Entry(body, textvariable=self.pwd_var, show="•", font=("Segoe UI", 11), bg="#0f172a", fg=fg, insertbackground=fg, relief="flat")
        self.ent_pwd.pack(fill="x", pady=(5, 10), ipady=7)
        self.ent_pwd.bind("<Return>", lambda _e: self._on_submit())

        self.new_pwd_frame = tk.Frame(body, bg=card)
        tk.Label(self.new_pwd_frame, text="3. New Password (min 4 characters):", font=("Segoe UI", 10, "bold"), bg=card, fg=fg).pack(anchor="w")
        self.ent_new_pwd = tk.Entry(self.new_pwd_frame, textvariable=self.new_pwd_var, show="•", font=("Segoe UI", 11), bg="#0f172a", fg=fg, insertbackground=fg, relief="flat")
        self.ent_new_pwd.pack(fill="x", pady=(5, 10), ipady=7)

        self.confirm_frame = tk.Frame(body, bg=card)
        self.lbl_confirm = tk.Label(self.confirm_frame, text="3. Confirm Password:", font=("Segoe UI", 10, "bold"), bg=card, fg=fg)
        self.lbl_confirm.pack(anchor="w")
        self.ent_confirm = tk.Entry(self.confirm_frame, textvariable=self.confirm_var, show="•", font=("Segoe UI", 11), bg="#0f172a", fg=fg, insertbackground=fg, relief="flat")
        self.ent_confirm.pack(fill="x", pady=(5, 10), ipady=7)
        self.ent_confirm.bind("<Return>", lambda _e: self._on_submit())

        opts = tk.Frame(body, bg=card)
        opts.pack(fill="x", pady=(2, 14))
        tk.Checkbutton(
            opts,
            text="Show Password",
            variable=self.show_pwd,
            command=self._toggle_pwd,
            bg=card,
            fg=muted,
            selectcolor="#0f172a",
            activebackground=card,
            activeforeground=fg,
            font=("Segoe UI", 9),
        ).pack(side="left")

        self.chk_open = tk.Checkbutton(
            opts,
            text="Open after unlock",
            variable=self.open_after_var,
            bg=card,
            fg=muted,
            selectcolor="#0f172a",
            activebackground=card,
            activeforeground=fg,
            font=("Segoe UI", 9),
        )

        self.btn_action = tk.Button(
            body,
            text="🔒 LOCK & CREATE ONE-CLICK .EXE",
            font=("Segoe UI", 10, "bold"),
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            relief="flat",
            pady=11,
            cursor="hand2",
            command=self._on_submit,
        )
        self.btn_action.pack(fill="x")

        ftr = tk.Frame(self.root, bg=bg)
        ftr.pack(fill="x", padx=24, pady=(0, 14))
        self.progress = ttk.Progressbar(ftr, mode="determinate", maximum=100)
        self.progress.pack(fill="x")
        tk.Label(ftr, textvariable=self.status_var, font=("Segoe UI", 9), bg=bg, fg=muted).pack(anchor="w", pady=(4, 0))

    def _switch_tab(self, mode: str):
        self.mode.set(mode)
        colors = {
            "lock": "#2563eb",
            "unlock": "#10b981",
            "change": "#d97706",
            "remove": "#dc2626",
        }
        for k, btn in self.tab_buttons.items():
            if k == mode:
                btn.configure(bg=colors[k], fg="#ffffff")
            else:
                btn.configure(bg="#1e293b", fg="#94a3b8")

        self.new_pwd_frame.pack_forget()
        self.confirm_frame.pack_forget()
        self.chk_open.pack_forget()

        if mode == "lock":
            self.lbl_desc.configure(text="Locks the item & creates '<Name> Lock.exe' beside it for 1-click lock / password unlock.", fg="#34d399")
            self.lbl_pwd.configure(text="2. Set Password (min 4 characters):")
            self.lbl_confirm.configure(text="3. Confirm Password:")
            self.confirm_frame.pack(fill="x", after=self.ent_pwd)
            self.btn_action.configure(text="🔒 LOCK & CREATE ONE-CLICK .EXE", bg="#2563eb", activebackground="#1d4ed8")
        elif mode == "unlock":
            self.lbl_desc.configure(text="Unlocks the item while keeping '<Name> Lock.exe' ready so you can 1-click lock again later.", fg="#38bdf8")
            self.lbl_pwd.configure(text="2. Enter Password:")
            self.chk_open.pack(side="right")
            self.btn_action.configure(text="🔓 UNLOCK ITEM", bg="#10b981", activebackground="#059669")
        elif mode == "change":
            self.lbl_desc.configure(text="Updates the password for both Master VaultLock and the '<Name> Lock.exe' toggle.", fg="#fbbf24")
            self.lbl_pwd.configure(text="2. Current Password:")
            self.new_pwd_frame.pack(fill="x", after=self.ent_pwd)
            self.lbl_confirm.configure(text="4. Confirm New Password:")
            self.confirm_frame.pack(fill="x", after=self.new_pwd_frame)
            self.btn_action.configure(text="🔑 UPDATE PASSWORD", bg="#d97706", activebackground="#b45309")
        elif mode == "remove":
            self.lbl_desc.configure(text="Permanently unlocks the item and deletes '<Name> Lock.exe' and its .vlock key.", fg="#f87171")
            self.lbl_pwd.configure(text="2. Enter Current Password to Remove Lock:")
            self.btn_action.configure(text="🗑️ REMOVE PASSWORD & DELETE TOGGLE .EXE", bg="#dc2626", activebackground="#b91c1c")

    def _toggle_pwd(self):
        ch = "" if self.show_pwd.get() else "•"
        self.ent_pwd.configure(show=ch)
        self.ent_new_pwd.configure(show=ch)
        self.ent_confirm.configure(show=ch)

    def _browse_file(self):
        p = filedialog.askopenfilename(title="Select File, .vlock Key, or Lock.exe")
        if p:
            self.path_var.set(p)
            _, key_file = _resolve_target_and_key(Path(p))
            if key_file.exists() and self.mode.get() == "lock":
                self._switch_tab("unlock")

    def _browse_folder(self):
        p = filedialog.askdirectory(title="Select Folder")
        if p:
            self.path_var.set(p)
            _, key_file = _resolve_target_and_key(Path(p))
            if key_file.exists() and self.mode.get() == "lock":
                self._switch_tab("unlock")

    def _set_progress(self, val: int, text: str):
        self._post_ui(lambda: (self.progress.configure(value=val), self.status_var.set(text)))

    def _on_install_menu(self):
        try:
            install_windows_context_menu()
            messagebox.showinfo("Success", "Added 'Manage Lock with VaultLock' to Windows Explorer right-click menu!")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _on_build_exe(self):
        def worker():
            try:
                exe = build_master_exe(self._set_progress)
                self._post_ui(
                    lambda: messagebox.showinfo(
                        "Master .exe Created",
                        f"Created Master executable:\n{exe}\n\nYou can now run VaultLock.exe directly without any terminal!",
                    )
                )
            except Exception as exc:
                msg = str(exc)
                self._post_ui(lambda: (self._set_progress(0, f"Error: {msg}"), messagebox.showerror("Build Failed", msg)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_submit(self):
        raw_path = self.path_var.get().strip().strip('"')
        pwd = self.pwd_var.get()
        if not raw_path:
            messagebox.showwarning("Missing Path", "Please select a file or folder first.")
            return
        if len(pwd) < 4:
            messagebox.showwarning("Weak Password", "Password must be at least 4 characters.")
            return

        mode = self.mode.get()
        new_pwd = self.new_pwd_var.get()
        confirm = self.confirm_var.get()

        if mode == "lock" and pwd != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match!")
            return
        if mode == "change":
            if len(new_pwd) < 4:
                messagebox.showwarning("Weak Password", "New password must be at least 4 characters.")
                return
            if new_pwd != confirm:
                messagebox.showerror("Mismatch", "New passwords do not match!")
                return

        target = Path(raw_path)
        self.btn_action.configure(state="disabled")

        def worker():
            try:
                if mode == "lock":
                    _, toggle_exe = lock_with_toggle_exe(target, pwd, self._set_progress)
                    self._post_ui(
                        lambda: messagebox.showinfo(
                            "Locked & Ready",
                            f"Locked:\n{target}\n\nCreated 1-Click Toggle .exe:\n{toggle_exe.name}\n\n• Click '{toggle_exe.name}' when locked -> asks password to unlock\n• Click '{toggle_exe.name}' when unlocked -> locks automatically in 1 click!",
                        )
                    )
                elif mode == "unlock":
                    restored = unlock_item(target, pwd, keep_toggle_exe=True, progress_cb=self._set_progress)
                    if self.open_after_var.get() and restored.exists() and os.name == "nt":
                        try:
                            os.startfile(str(restored))
                        except OSError:
                            pass
                    self._post_ui(lambda: messagebox.showinfo("Unlocked", f"Unlocked:\n{restored}\n\nClick '{restored.name} Lock.exe' anytime to re-lock in 1 click."))
                elif mode == "change":
                    restored = change_item_password(target, pwd, new_pwd, self._set_progress)
                    self._post_ui(lambda: messagebox.showinfo("Password Updated", f"Password changed successfully for:\n{restored.name}"))
                elif mode == "remove":
                    restored = remove_item_lock(target, pwd, self._set_progress)
                    self._post_ui(lambda: messagebox.showinfo("Lock Removed", f"Password and toggle .exe completely removed for:\n{restored}"))
            except Exception as exc:
                msg = str(exc)
                self._post_ui(lambda: (self._set_progress(0, f"Error: {msg}"), messagebox.showerror("Operation Failed", msg)))
            finally:
                self._post_ui(lambda: self.btn_action.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def run(self):
        self.root.mainloop()


def _handle_fallback_clone_toggle(exe_path: Path) -> bool:
    """If VaultLock.exe was copied as '<ItemName> Lock.exe' (fallback when csc.exe is absent), act as 1-click toggle."""
    if not exe_path.name.endswith(" Lock.exe"):
        return False
    target, key_file = _resolve_target_and_key(exe_path)
    if not key_file.exists() or not target.exists():
        return False

    _clear_win_attributes(key_file)
    meta = json.loads(key_file.read_text(encoding="utf-8-sig"))
    if not meta.get("locked", True):
        # Re-lock immediately in 1 click
        perm = "(OI)(CI)(F)" if target.is_dir() else "(F)"
        _run_silent(["icacls", str(target), "/deny", f"*S-1-1-0:{perm}", "/C", "/Q"], timeout=30)
        meta["locked"] = True
        key_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        if HAS_TK:
            r = tk.Tk()
            r.withdraw()
            messagebox.showinfo("VaultLock", f"Locked: {target.name}")
            r.destroy()
        return True

    # Locked -> open Master UI focused on unlock tab
    if HAS_TK:
        VaultLockMasterApp(initial_path=str(target)).run()
    return True


def main():
    if getattr(sys, "frozen", False):
        if _handle_fallback_clone_toggle(Path(sys.executable)):
            return

    parser = argparse.ArgumentParser(description="VaultLock — Master Locker & One-Click .exe Generator")
    parser.add_argument("action", nargs="?", help="lock | unlock | change-password | remove-lock | path")
    parser.add_argument("target", nargs="?", help="Target file or folder path")
    parser.add_argument("-p", "--password", help="Current password")
    parser.add_argument("-n", "--new-password", help="New password (for change-password)")
    args = parser.parse_args()

    if args.action and args.action not in ("lock", "unlock", "change-password", "remove-lock"):
        if not HAS_TK:
            sys.exit("Tkinter is required for GUI mode.")
        VaultLockMasterApp(initial_path=args.action).run()
        return

    if args.action in ("lock", "unlock", "change-password", "remove-lock"):
        if not args.target:
            parser.error(f"'{args.action}' requires a target path.")
        t = Path(args.target)
        pwd = args.password or getpass.getpass("Password: ")
        if args.action == "lock":
            _, toggle = lock_with_toggle_exe(t, pwd)
            print(f"Locked -> {t} | 1-Click Toggle -> {toggle}")
        elif args.action == "unlock":
            out = unlock_item(t, pwd, keep_toggle_exe=True)
            print(f"Unlocked -> {out}")
        elif args.action == "change-password":
            new_pwd = args.new_password or getpass.getpass("New Password: ")
            out = change_item_password(t, pwd, new_pwd)
            print(f"Password updated -> {out}")
        elif args.action == "remove-lock":
            out = remove_item_lock(t, pwd)
            print(f"Lock & toggle .exe removed -> {out}")
        return

    if not HAS_TK:
        parser.print_help()
        return
    VaultLockMasterApp().run()


if __name__ == "__main__":
    main()