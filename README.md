# 📊 StatusPulse

**Minimalistic API Monitoring SaaS built in Rust**  
_Simple. Fast. Yours._

StatusPulse is a lightweight uptime monitoring service for developers, freelancers, and indie makers.  
It keeps an eye on your APIs, notifies you when something breaks, and stays out of your way.  
No bloated dashboards. No overkill enterprise nonsense. Just clean, efficient monitoring — Rust style.

---

## 🚀 Features

- ✅ **API Uptime Monitoring** — periodic health checks with configurable intervals
- ✅ **Email Alerts via SendGrid** — instant notifications when a monitor goes down
- ✅ **Status Logs & History** — response times & uptime percentage tracking
- ✅ **JWT Authentication** — secure access for users
- ✅ **Tera-based Frontend Dashboard** — simple & fast UI (SSR)
- ✅ **MySQL with SQLx** — reliable data persistence
- ✅ **Background Workers** — efficient ping cycles using Tokio

---

## 🛠 Tech Stack

- **Rust** (Axum, Tokio, SQLx)
- **Tera Templates** (SSR frontend)
- **SendGrid API** (email notifications)
- **MySQL** (SQLx & Migrations)
- Fully async & production-ready.

---

## 📦 Project Structure

```
/src
 ├── db/                 # SQLx repositories & queries
 ├── handlers/           # API endpoints & logic
 ├── services/           # SendGrid, workers, email templates
 ├── models/             # Data models (User, Monitor, StatusLog, etc.)
 ├── templates/          # Tera HTML templates
 ├── routes.rs           # API routes setup
 ├── worker.rs           # Background ping & alert service
 └── main.rs             # App entry & router
```

---

## 🏁 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/statuspulse.git
cd statuspulse
```

### 2. Configure environment
Create a `.env` file:
```env
DATABASE_URL=mysql://username:password@localhost/statuspulse
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=alerts@statuspulse.app
```

### 3. Run migrations
```bash
sqlx migrate run
```

### 4. Start the app
```bash
cargo run
```

### 5. Access the dashboard
Open: [http://localhost:3000](http://localhost:3000)

---

## 📊 API Endpoints

### 🖥️ Monitors
- `GET /monitors` → List all monitors
- `GET /monitors/active` → List active monitors
- `GET /monitors/inactive` → List inactive monitors
- `POST /monitors` → Add a new monitor
- `PUT /monitors/:id` → Update an existing monitor
- `DELETE /monitors/:id` → Delete a monitor

### 📈 Monitor Status & Logs
- `GET /monitors/:id/status` → Get monitor status summary (uptime %, last log, avg response time)
- `GET /monitors/:id/logs` → Get monitor's log history

### 🔐 Authentication
- `POST /auth/register` → Register a new user
- `POST /auth/login` → User login (returns JWT token)
- `GET /auth/me` → Get current authenticated user info

### 🛠️ Health & System
- `GET /health` → Application health check

---

## 📝 Roadmap (Next steps)

- [ ] Webhooks (Slack, Discord, etc.)
- [ ] Public Status Pages
- [ ] API Token Management
- [ ] Usage Analytics & Reports

---

## 📄 License

Private for now.  
Open-source coming soon.

---

## 💡 Why Rust?
Because you want your monitoring tool to be faster than your failing API.  
StatusPulse is built to be efficient, reliable, and developer-friendly.

---

> _Made with 🦀 by Emir Totić_