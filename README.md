# LAN Chat

> CRITICAL: This is a 100% vibe coded project don't run this on the wider internet and never allow untrusted access to this program.

LAN Chat is a lightweight local-network chat app using Deno, WebSockets, and a browser frontend with room-key encryption.

## Features

- Account access with `username + PIN`
- Sign-up and sign-in flow in the UI
- Root admin account with user management:
  - View registered users
  - Delete user accounts (and their messages)
  - Wipe all non-admin users + clear room history
- Persistent account storage using SQLite (`backend/chat.sqlite3`)
- Room-based chat (`General` + custom rooms)
- Client-side room-key encryption (AES-GCM via Web Crypto)
- Message replies and spoiler messages
- Notification system:
  - In-app toasts
  - Desktop notifications (optional)
  - Sound notifications via `frontend/static/sound/discord_message.mp3`
- Per-user mute/unmute
- Local storage for:
  - Username + avatar
  - Theme (WIP)
  - Notification settings
  - Muted users

## Root Admin

- Default root account is:
  - Username: `root`
  - PIN: `0000`

Change it immediately in production by updating the value in `backend/main.ts`.

## Deployment

### Prerequisites

- [Deno](https://deno.com/)

### Local Development

1.  **Run Dev**:
    ```bash
    deno task dev
    ```
2.  **Access**: Open `http://localhost:8000`.

### LAN Deployment

1.  **Build Frontend**:
    ```bash
    deno task build:fe
    ```
2.  **Start Server**:
    ```bash
    deno task start --allow-all
    ```
3.  **Access the App**:
    - Locally: `http://localhost:8000`
    - LAN Access: Use your computer's local IP (e.g., `http://192.168.1.5:8000`).

### Build a Standalone Binary

The binary is compiled with `--allow-all`, so permissions are baked in at build time and users do not see runtime permission prompts.

1.  **Build Binary**:
    ```bash
    deno task build:bin
    ```
2.  **Run Binary**:
    ```bash
    ./bin/lan-chat
    ```
3.  **Access the App**:
    - Locally: `http://localhost:8000`
    - LAN Access: `http://<your-local-ip>:8000`

### GitHub Binary Builds

This repo includes a workflow at `.github/workflows/build-binaries.yml` that builds binaries for:
- Linux (`x86_64-unknown-linux-gnu`)
- Windows (`x86_64-pc-windows-msvc`)
- macOS (`x86_64-apple-darwin`)

Trigger it with:
- Pushes to `master`
- Pull requests to `master`
- Manual run from the Actions tab (`workflow_dispatch`)

The workflow always uploads compiled binaries as artifacts.
For non-PR runs (`push` to `master` and `workflow_dispatch`), it also creates a GitHub prerelease and attaches the binaries there.

### Data Persistence

- SQLite database: `./backend/chat.sqlite3`
- Uploads: `./frontend/static/uploads`


## Keyboard Shortcuts

- `Enter`: Send message
- `Shift + Enter`: New line
- `Alt + S`: Toggle spoiler mode
- `N`: Create room
- `T`: Focus theme selector
- `Esc`: Cancel reply
- `Alt + Q`: Logout

## Project Structure

```text
backend/main.ts                 # API + WebSocket server + auth + admin
backend/chat.sqlite3            # SQLite database file
frontend/index.html             # UI layout/styles
frontend/app.ts                 # Frontend logic
frontend/dist/app.js            # Bundled frontend script
frontend/static/sound/*.mp3     # Notification sound assets
frontend/themes/*.css           # Theme files
```

## Notes

- PIN format: numeric, 4-12 digits.
- Usernames: 3-24 chars using letters, numbers, `_`, `-`, `.`
- Message history is in-memory and resets on server restart.
