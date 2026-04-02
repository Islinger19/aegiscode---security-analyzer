<p align="center">
  <img src="resources/icon.png" alt="AegisCode Logo" width="128" height="128" />
</p>

<h1 align="center">AegisCode — Security Analyzer</h1>

<p align="center">
  <strong>AI-powered code analysis for Python — helping developers write more secure code every day.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#%EF%B8%8F-how-it-works">How It Works</a> •
  <a href="#-detection-coverage">Coverage</a> •
  <a href="#%EF%B8%8F-settings">Settings</a> •
  <a href="#-commands">Commands</a>
</p>

---

## ✨ Features

### 🔍 Real-Time Code Analysis
AegisCode continuously scans your Python code as you write. Issues are highlighted directly in your editor with severity-coded diagnostics — no manual scanning required.

- **Analyze on Save** — Automatic analysis every time you save a file
- **Analyze on Type** — Optional live analysis as you type (configurable delay)
- **Analyze on Open** — Files are analyzed as soon as they're opened

### 🤖 AI-Powered Explanations & Fixes
Go beyond just flagging issues. AegisCode leverages LLM models to provide:

- **Beginner-friendly explanations** — Understand *why* a pattern is problematic
- **Real-world context** — Learn how each issue could impact your application
- **Secure code fixes** — Get the exact replacement code to resolve each issue

### ⚡ Copilot-Style Inline Fix Suggestions
When your cursor is on a flagged line, AegisCode presents ghost-text inline suggestions — just press **Tab** to accept the secure fix. No menus, no context switching.

### 💡 Quick Fix (Lightbulb) Actions
Each detected issue comes with:
- **🔒 Apply Fix** — One-click secure code replacement
- **📚 Learn More** — Direct links to OWASP, CWE, and educational resources

### 🔗 Cross-File Analysis
AegisCode doesn't just look at one file in isolation. Enable **multi-file analysis** to detect data-flow issues that span across your project:
- Track data flowing from one module to another
- Identify unsanitized inputs reaching sensitive operations in different files
- Full data-flow path tracing with source → sink mapping

### 📦 CVE Database Lookups
Automatically identifies known CVEs for the packages you import. Get notified about dependencies with known issues, including severity scores, CVSS ratings, and upgrade recommendations.

### 📊 Dedicated Sidebar Panel
A custom activity bar with three organized views:

| View | Description |
|------|-------------|
| **Account** | Login with Google, view your stats, and access the web dashboard |
| **Issues** | All findings organized by file with color-coded severity indicators |
| **Summary** | At-a-glance breakdown: total, critical, high, medium, and low counts |

### 🔐 Google Authentication & Cloud Sync
Sign in with Google to unlock:
- **Analysis History** — Every scan is saved to your personal cloud profile
- **Statistics** — Track total analyses, issues found, and fixes applied
- **Web Dashboard** — Access your data from any browser
- **Fixes Tracking** — See how your secure coding practices improve over time

### 🧠 Smart Caching
Avoid redundant work with content-based caching:
- Results are cached locally with a 7-day TTL
- Identical content is never analyzed twice
- Cache persists across VS Code sessions

### 🖱️ Rich Hover Tooltips
Hover over any highlighted issue to see a detailed tooltip with:
- What's wrong
- Why it matters
- How it could affect your application
- How to fix it
- Secure code example
- CWE / OWASP references

---

## 🚀 Quick Start

1. **Install the extension** from the VS Code Marketplace
2. **Start the backend server** (see [Backend Setup](#backend-setup) below)
3. **Open any Python file** — analysis begins automatically

That's it. No configuration needed to get started.

### Backend Setup

AegisCode requires a companion backend server for analysis:

```bash
cd backend
pip install -r requirements.txt
python run.py
```

The server starts on your local machine by default. You can configure the server URL in extension settings.

> **Tip:** The backend supports multiple LLM providers — Ollama (local), OpenAI, and HuggingFace. See the project documentation for LLM configuration.

---

## ⚙️ How It Works

```
┌─────────────────────┐      HTTP/JSON       ┌──────────────────────┐
│  VS Code Extension  │ ──────────────────►   │   Python Backend     │
│  (TypeScript)       │                       │   (FastAPI)          │
│                     │ ◄──────────────────   │                      │
│  • Diagnostics      │   Analysis Results    │  • Static Analyzer   │
│  • Inline Fixes     │   + AI Explanations   │  • LLM Analyzer      │
│  • Hover Tooltips   │   + Fix Suggestions   │  • Multi-File Engine  │
│  • Sidebar Views    │                       │  • CVE Database       │
│  • Auth & History   │                       │  • Auth & History API │
└─────────────────────┘                       └──────────────────────┘
```

1. **You write Python code** in VS Code
2. **AegisCode sends your code** to the backend on save/type/open
3. **The backend runs static analysis** (regex + AST pattern matching) to detect 10+ issue types
4. **The LLM enhances results** with beginner-friendly explanations and fix suggestions
5. **Results appear instantly** as editor diagnostics, hover tooltips, inline suggestions, and sidebar items

---

## 🛡️ Detection Coverage

AegisCode detects **10+ categories** of common Python code issues:

| Category | Severity |
|----------|----------|
| **Hard-coded Credentials** | 🔴 Critical |
| **SQL Injection Patterns** | 🔴 Critical |
| **Command Injection Patterns** | 🔴 Critical |
| **Insecure Deserialization** | 🟠 High |
| **Path Traversal** | 🟠 High |
| **Dangerous Function Usage** | 🟠 High |
| **Weak Cryptography** | 🟡 Medium |
| **Insecure SSL/TLS Configuration** | 🟡 Medium |
| **Debug Mode in Production** | 🟡 Medium |
| **Insecure Random Number Generation** | 🟢 Low |

Each detection includes **CWE identifiers** and **OWASP Top 10** category mappings.

---

## ⌨️ Commands

Access all commands via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description |
|---------|-------------|
| `AegisCode: Analyze Current File` | Scan the active Python file |
| `AegisCode: Analyze Workspace (Multi-File)` | Scan all Python files with cross-file detection |
| `AegisCode: Show Security Analysis Panel` | Open the sidebar panel |
| `AegisCode: Clear Security Warnings` | Remove all diagnostics |
| `AegisCode: Clear Analysis Cache` | Reset the local cache |
| `AegisCode: Login with Google` | Authenticate to enable cloud sync |
| `AegisCode: Logout` | Sign out of your account |
| `AegisCode: View Security Statistics` | Open your stats dashboard |
| `AegisCode: View Analysis History` | Browse past analyses |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+Shift+.` (Mac) / `Ctrl+Shift+.` (Win/Linux) | Apply fix for current line |

### Context Menu

Right-click on any Python file in the editor to access **"Analyze Current File"** directly from the context menu.

---

## 🛠️ Settings

Configure AegisCode via `File > Preferences > Settings` (search for "Security Analyzer"):

| Setting | Default | Description |
|---------|---------|-------------|
| `serverUrl` | `localhost:8000` | Backend server URL |
| `analyzeOnSave` | `true` | Auto-analyze when files are saved |
| `analyzeOnType` | `false` | Live analysis as you type |
| `analyzeOnTypeDelay` | `1000` | Debounce delay (ms) for type analysis |
| `minSeverity` | `low` | Minimum severity to display: `low` / `medium` / `high` / `critical` |
| `enableAiExplanations` | `true` | Use LLM for enhanced explanations |
| `showInlineHints` | `true` | Show inline diagnostic hints |
| `enableInlineSuggestions` | `true` | Enable Copilot-style ghost-text fixes |
| `saveAnalysisHistory` | `true` | Sync analysis results to cloud (requires login) |
| `saveCodeSnippetsToHistory` | `true` | Include source code in saved history |
| `multiFileAnalysis` | `true` | Enable cross-file detection |
| `enableCveLookup` | `true` | Auto-lookup CVEs for imported packages |

---

## 📋 Requirements

- **VS Code** 1.109.0 or later
- **Python files** in your workspace
- **Backend server** running locally (see Quick Start)
- For AI explanations: an LLM provider (Ollama, OpenAI, or HuggingFace) configured on the backend

---

## 🔄 Release Notes

### 0.0.1 — Initial Release
- Real-time code analysis with 10+ detection categories
- AI-powered explanations and fix suggestions via LLM integration
- Copilot-style inline completion for fixes (Tab to accept)
- Quick Fix lightbulb actions with one-click patch application
- Cross-file multi-module analysis
- CVE database lookups for imported packages
- Google OAuth authentication with cloud sync
- Analysis history and statistics dashboard
- Dedicated sidebar with Account, Issues, and Summary views
- Rich hover tooltips with CWE/OWASP references
- Content-based caching with 7-day TTL
- Context menu integration and keyboard shortcuts

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with 🛡️ by <strong>AegisCode</strong> — Because secure code starts where you write it.</sub>
</p>
