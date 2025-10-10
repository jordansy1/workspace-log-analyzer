# Workspace Log Analyzer - Web UI

Modern React web interface for the Google Workspace Authentication Log Analyzer.

## Architecture

```
┌──────────────────┐
│ React Frontend   │  Port 5173 (Vite dev server)
│ (TypeScript)     │
└────────┬─────────┘
         │ REST API
         ▼
┌──────────────────┐
│ FastAPI Backend  │  Port 8000
│ (Python)         │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Python Modules   │
│ (fetch_logs,     │
│  orchestrator,   │
│  enrichment)     │
└──────────────────┘
```

## Tech Stack

### Frontend
- **React 18** with TypeScript
- **Vite** for build tooling
- **Tailwind CSS** for styling
- **TanStack Table** for data tables
- **TanStack Query** (React Query) for server state management
- **React Router** for navigation
- **Axios** for HTTP requests
- **Lucide React** for icons
- **date-fns** for date formatting

### Backend
- **FastAPI** for REST API
- **Google OAuth 2.0** for authentication
- **Python 3.x** integration with existing modules

## Features

- ✅ **Google OAuth Login** - Secure "Sign in with Google" flow
- ✅ **Configurable Time Range** - 1 hour to 7 days lookback
- ✅ **Real-time Log Fetching** - Pull authentication logs on demand
- ✅ **Enriched Data Display** - IP reputation, geolocation, user context
- ✅ **AI-Powered Analysis** - Multi-agent anomaly detection
- ✅ **Interactive Table** - Sortable, filterable, paginated events
- ✅ **Detail Drawer** - Slide-over panel with full event context
- ✅ **Visual Risk Indicators** - Color-coded severity and risk scores

## Setup

### Prerequisites

1. Complete the main project setup from parent README
2. Ensure Python virtual environment is activated
3. Have `credentials.json` in the parent directory

### 1. Install Backend Dependencies

```bash
cd workspace_log_analyzer/web-ui/backend
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies

```bash
cd workspace_log_analyzer/web-ui/frontend
npm install
```

### 3. Configure Google OAuth Redirect URI

In [Google Cloud Console](https://console.cloud.google.com):

1. Go to APIs & Services → Credentials
2. Edit your OAuth 2.0 Client ID
3. Add to "Authorized redirect URIs":
   ```
   http://localhost:8000/auth/callback
   ```
4. Add to "Authorized JavaScript origins":
   ```
   http://localhost:5173
   http://localhost:8000
   ```
5. Save changes

## Running the Application

### Start Backend (Terminal 1)

```bash
cd workspace_log_analyzer/web-ui/backend
python main.py
```

Backend will start on `http://localhost:8000`

### Start Frontend (Terminal 2)

```bash
cd workspace_log_analyzer/web-ui/frontend
npm run dev
```

Frontend will start on `http://localhost:5173`

### Open Application

Navigate to `http://localhost:5173` in your browser

## Usage Flow

### 1. Authentication
- Click "Sign in with Google"
- Authorize access to Google Workspace Admin SDK
- Redirected back to dashboard

### 2. Fetch Logs
- Select lookback period (default: 24 hours)
- Click "Fetch Logs"
- View enriched authentication events in table

### 3. Run Analysis
- Click "Run Analysis" after logs are fetched
- AI sub-agents analyze each potential anomaly
- Table highlights suspicious events with red background

### 4. View Details
- Click any table row to open detail drawer
- See enriched context (IP reputation, location, user info)
- For suspicious events, view AI analysis:
  - Risk assessment
  - Scenario identification
  - Confidence level
  - Detailed reasoning
  - Recommendations

## API Endpoints

### Authentication
- `GET /auth/login` - Initiate OAuth flow
- `GET /auth/callback` - OAuth callback handler
- `GET /auth/me` - Get current user info

### Logs
- `POST /api/logs/fetch` - Fetch authentication logs
- `GET /api/logs/{filename}` - Get log file details

### Analysis
- `POST /api/analysis/run` - Run automated analysis
- `GET /api/analysis/{filename}` - Get analysis results

### Utility
- `GET /health` - Health check

## Development

### Frontend Development

```bash
cd frontend
npm run dev      # Start dev server
npm run build    # Production build
npm run preview  # Preview production build
npm run lint     # Run ESLint
```

### Backend Development

The FastAPI backend uses:
- Auto-reload on code changes (via uvicorn)
- Interactive API docs at `http://localhost:8000/docs`
- Alternative docs at `http://localhost:8000/redoc`

### Project Structure

```
web-ui/
├── backend/
│   ├── main.py              # FastAPI application
│   └── requirements.txt     # Python dependencies
│
└── frontend/
    ├── src/
    │   ├── components/      # Reusable components
    │   │   ├── Button.tsx
    │   │   ├── EventsTable.tsx
    │   │   └── AnalysisDrawer.tsx
    │   │
    │   ├── pages/           # Page components
    │   │   ├── LoginPage.tsx
    │   │   ├── AuthSuccessPage.tsx
    │   │   └── DashboardPage.tsx
    │   │
    │   ├── lib/             # Utilities
    │   │   ├── api.ts       # API client & types
    │   │   └── utils.ts     # Helper functions
    │   │
    │   ├── App.tsx          # Root component with routing
    │   ├── main.tsx         # Entry point
    │   └── index.css        # Global styles
    │
    ├── package.json
    ├── tailwind.config.js
    ├── tsconfig.json
    └── vite.config.ts
```

## Security Notes

### Development Mode
- In-memory session storage (not production-ready)
- No HTTPS (use for local development only)
- CORS configured for localhost

### Production Considerations
For production deployment, you'll need:
- Redis or database for session storage
- JWT tokens instead of simple session tokens
- HTTPS/TLS encryption
- Proper CORS configuration
- Rate limiting
- Session expiration and refresh token handling

## Troubleshooting

### OAuth Errors

**"redirect_uri_mismatch"**
- Verify redirect URI in Google Cloud Console matches exactly: `http://localhost:8000/auth/callback`

**"invalid_client"**
- Ensure `credentials.json` exists in parent directory
- Check credentials file has correct client_id and client_secret

### Backend Errors

**"Module not found"**
```bash
# Ensure you're running from the correct directory
cd workspace_log_analyzer/web-ui/backend
# And that parent modules are accessible
python -c "import sys; sys.path.append('../../'); from fetch_logs import WorkspaceLogFetcher"
```

**"credentials.json not found"**
- Copy `credentials.json` to `workspace_log_analyzer/` directory

### Frontend Errors

**CORS errors**
- Ensure backend is running on port 8000
- Check CORS middleware in `backend/main.py` allows `http://localhost:5173`

**"Network Error"**
- Verify backend is running: `curl http://localhost:8000/health`

## Future Enhancements

- [ ] Real-time log streaming with WebSockets
- [ ] Dashboard charts and visualizations
- [ ] Export analysis reports to PDF
- [ ] Multi-workspace support
- [ ] Scheduled analysis with email alerts
- [ ] Historical trend analysis
- [ ] Custom alert rules configuration
- [ ] Dark mode support

## License

MIT License - Same as parent project
