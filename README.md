# LAN Chat

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

- [Deno](https://deno.com/) (for local development)
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/) (for production/LAN)

### Local Development

1.  **Run Dev**:
    ```bash
    deno task dev
    ```
2.  **Access**: Open `http://localhost:8000`.

### Docker Deployment (Recommended for LAN)

This setup ensures data persistence and easy access across your network.

1.  **Build and Start**:
    ```bash
    docker-compose up -d --build
    ```
2.  **Access the App**:
    - Locally: `http://localhost:8000`
    - LAN Access: Use your computer's local IP (e.g., `http://192.168.1.5:8000`).

### Data Persistence in Docker

The Docker setup uses volumes to protect your data during updates:
- `./backend-data`: Stores the SQLite database.
- `./uploads`: Stores all shared files and images.


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
