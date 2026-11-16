# VaultLock — Windows File, Folder, Image & Video Locker

**VaultLock** is a fast, lightweight Windows locker with both a modern **GUI** and **CLI**. Instead of slowly copying or re-archiving gigabytes of data, VaultLock locks any file, folder, image, or video **in-place in under 0.1 seconds** while keeping all internal contents completely untouched.

On first lock, VaultLock generates a standalone **`<ItemName> Lock.exe`** right next to your protected item:

* **Click once when unlocked** -> Locks immediately in one click (no password prompt needed to re-lock).
* **Click again when locked** -> Prompts for your password and unlocks/opens your item.
* **Master `VaultLock.exe` (`masterLock.py`)** -> Centrally set passwords, unlock items, change passwords, or permanently remove locks and toggle executables.

## Key Features

* **Zero-Install Standalone Executable (`VaultLock.exe`):** Download and run directly on Windows 10/11 without installing Python or external packages.
* **Instant In-Place Locking (`< 0.1s`):** Locks folders and files of any size (including multi-GB video folders) using Windows NTFS Access Control Lists (`icacls`) without moving, renaming, or deleting any internal files.
* **One-Click Companion Toggle (`<ItemName> Lock.exe`):** Automatically compiles a lightweight (~16 KB) native Windows executable beside each protected item for effortless one-click locking and password-protected unlocking.
* **Master Control Panel:** Manage all locked items from a single resizable dark-mode interface—set up new locks, unlock items, change passwords, or remove locks cleanly.
* **Windows Explorer Integration:** Add **Manage Lock with VaultLock** directly to your Windows right-click context menu in one click.
* **Full GUI & CLI Support:** Use the visual interface or automate lock, unlock, and password workflows from Command Prompt or PowerShell.
* **Salted PBKDF2-HMAC-SHA256 Password Verification:** Passwords are never stored in plain text; every `.vlock` key file uses a unique 16-byte cryptographic salt and 200,000 PBKDF2-HMAC-SHA256 iterations.

## Quick Start

### Option 1: Download & Run `VaultLock.exe` Directly (Recommended — No Python Needed)

1. Download **`VaultLock.exe`** from the repository files or the **Releases** page.
2. Double-click **`VaultLock.exe`** to launch the Master Control Panel.
   * *Note on Windows SmartScreen:* Because `VaultLock.exe` is a community open-source binary without a paid code-signing certificate, Windows Defender SmartScreen may show *"Windows protected your PC"* on the first launch. Click **More info** -> **Run anyway** to proceed.
3. *(Optional)* Click **Right-Click Menu** in the top-right corner of the app to add **Manage Lock with VaultLock** to your Windows File Explorer context menu.

### Option 2: Run from Python Source

* **Requirements:** Windows 10 or Windows 11, Python 3.8+ (includes `tkinter`).

```bash
git clone https://github.com/Divyanshuk009/Master-locker.git
cd Master-locker
python masterLock.py
```

To build your own standalone `VaultLock.exe` from source, click **Build Master .exe** inside the app (requires `pip install pyinstaller`).

## Usage Guide

### Graphical User Interface (GUI)

1. **First-Time Lock Setup (`Lock Setup` tab):**
   * Select any file, image, video, or folder.
   * Enter and confirm a password (minimum 4 characters).
   * Click **LOCK & CREATE ONE-CLICK .EXE**.
   * Your item is locked immediately, and **`<ItemName> Lock.exe`** + **`<ItemName>.vlock`** are created beside it.

2. **Daily One-Click Toggle (`<ItemName> Lock.exe`):**
   * **To Unlock:** Double-click **`<ItemName> Lock.exe`**, enter your password, and press **Enter** (automatically opens the folder or file if *"Open after unlock"* is checked).
   * **To Re-Lock:** Double-click **`<ItemName> Lock.exe`** again—it locks immediately with a brief confirmation toast.

3. **Change Password (`Change Password` tab):**
   * Select the item (or its `.vlock` / `Lock.exe` file), enter your current password and new password, and click **UPDATE PASSWORD**. Both `VaultLock.exe` and `<ItemName> Lock.exe` immediately enforce the new password.

4. **Remove Lock (`Remove Lock` tab):**
   * Select the item, enter your password, and click **REMOVE PASSWORD & DELETE TOGGLE .EXE** to permanently restore permissions and delete the `.vlock` and `<ItemName> Lock.exe` files.

### Command-Line Interface (CLI)

Run any command from Command Prompt or PowerShell using either `VaultLock.exe` or `python masterLock.py`:

| Action | Command |
| :--- | :--- |
| **Lock & create toggle `.exe`** | `VaultLock.exe lock "D:\Media\PrivateFolder" -p yourpassword` |
| **Unlock item** | `VaultLock.exe unlock "D:\Media\PrivateFolder" -p yourpassword` |
| **Change password** | `VaultLock.exe change-password "D:\Media\PrivateFolder" -p oldpass -n newpass` |
| **Remove lock & toggle `.exe`** | `VaultLock.exe remove-lock "D:\Media\PrivateFolder" -p newpass` |
| **Open specific item in GUI** | `VaultLock.exe "D:\Media\PrivateFolder"` |

> **Tip:** Omit `-p` / `-n` flags in CLI mode to be prompted securely without saving passwords in your terminal history.

## How It Works

1. **NTFS Access Control:** VaultLock applies explicit NTFS `Deny` permissions (`icacls /deny *S-1-1-0:(OI)(CI)(F)`) on the target path, blocking unauthorized browsing, copying, or deletion in Windows Explorer and Command Prompt while leaving internal files untouched.
2. **Metadata & Verification:** A companion `<ItemName>.vlock` JSON file stores the lock state (`locked: true/false`), random 16-byte salt, and PBKDF2-HMAC-SHA256 hash.
3. **Native Toggle Compilation:** When locking an item for the first time, VaultLock invokes Windows' built-in .NET C# compiler (`csc.exe`) to compile a self-contained WinForms toggle executable (`<ItemName> Lock.exe`) tailored to that item.

## Important Notes

* **Keep `<ItemName>.vlock` Beside the Item:** `<ItemName> Lock.exe` relies on the companion `<ItemName>.vlock` file in the same directory to verify your password and track lock state. Do not delete the `.vlock` file manually while an item is locked.
* **Remember Your Password:** Because passwords are hashed with PBKDF2-HMAC-SHA256, there is no plain-text password recovery.
* **NTFS Drives:** Instant ACL locking requires an NTFS-formatted Windows drive (standard for internal Windows drives like `C:` and `D:`).

## License

This project is open-source.
