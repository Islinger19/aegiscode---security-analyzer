# AegisCode - Security Analyzer

AI-powered security vulnerability detection for Python code - designed for beginners.

## Features

- **Real-time Security Analysis**: Automatically analyzes Python files for security vulnerabilities as you save or type
- **AI-Powered Explanations**: Get beginner-friendly explanations of vulnerabilities and how to fix them
- **Interactive Sidebar**: View all vulnerabilities organized by file with severity indicators
- **Hover Information**: Hover over highlighted code to see detailed vulnerability information
- **Severity Filtering**: Configure minimum severity level to display (low, medium, high, critical)
- **Workspace Analysis**: Analyze all Python files in your workspace at once

## Requirements

- A running instance of the Python Security Analyzer backend server (default: http://127.0.0.1:8000)
- Python files in your workspace

## Extension Settings

This extension contributes the following settings:

- `pythonSecurityAnalyzer.serverUrl`: URL of the security analyzer backend server (default: `http://127.0.0.1:8000`)
- `pythonSecurityAnalyzer.analyzeOnSave`: Automatically analyze files when saved (default: `true`)
- `pythonSecurityAnalyzer.analyzeOnType`: Analyze files as you type (default: `false`)
- `pythonSecurityAnalyzer.analyzeOnTypeDelay`: Delay in milliseconds before analyzing while typing (default: `1000`)
- `pythonSecurityAnalyzer.minSeverity`: Minimum severity level to display (`low`, `medium`, `high`, `critical`)
- `pythonSecurityAnalyzer.enableAiExplanations`: Enable AI-powered explanations (default: `true`)
- `pythonSecurityAnalyzer.showInlineHints`: Show inline hints for vulnerabilities (default: `true`)

## Commands

- `Python Security: Analyze Current File for Security Vulnerabilities` - Analyze the currently open Python file
- `Python Security: Analyze Workspace for Security Vulnerabilities` - Analyze all Python files in the workspace
- `Python Security: Show Security Analysis Panel` - Open the security analysis sidebar
- `Python Security: Clear Security Warnings` - Clear all security diagnostics

## Known Issues

- Backend server must be running for analysis to work

## Release Notes

### 1.0.0

Initial release of AegisCode Security Analyzer

---

## Following extension guidelines

Ensure that you've read through the extensions guidelines and follow the best practices for creating your extension.

- [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)

## Working with Markdown

You can author your README using Visual Studio Code. Here are some useful editor keyboard shortcuts:

- Split the editor (`Cmd+\` on macOS or `Ctrl+\` on Windows and Linux).
- Toggle preview (`Shift+Cmd+V` on macOS or `Shift+Ctrl+V` on Windows and Linux).
- Press `Ctrl+Space` (Windows, Linux, macOS) to see a list of Markdown snippets.

## For more information

- [Visual Studio Code's Markdown Support](http://code.visualstudio.com/docs/languages/markdown)
- [Markdown Syntax Reference](https://help.github.com/articles/markdown-basics/)

**Enjoy!**
