![Logo](logo.png)
# CodeReviewer.AI

CodeReviewer.AI is an **advanced security-focused** automated pull request review bot that leverages artificial intelligence to analyze code changes for vulnerabilities and security issues. It uses Groq's language model combined with pattern-based security scanning to provide comprehensive security reviews.

## 🛡️ Security Features
- **Automated vulnerability detection** using regex patterns for common security issues
- **CVE scanning** for dependencies using Safety database
- **Human-like, concise security reviews** with actionable feedback
- **Real-time security analysis** of code changes
- **Pattern-based detection** for SQL injection, XSS, path traversal, hardcoded secrets, and more
- **Dependency vulnerability scanning** for known CVEs

## Technologies Used
- **Groq**: We use Groq’s Llama-based model for code review and suggestions.
- **GitHub API**: To interact with the GitHub repository and fetch pull requests.
- **Python**: The main programming language used for developing this bot.
- **GitHub Actions**: For automating the execution of the bot in response to pull requests.

## Requirements 

You will need the following dependencies:

- `groq`: For interacting with Groq's API.
- `requests`: For making API requests to GitHub.
- `pygments`: For code syntax highlighting.
- `safety`: For CVE vulnerability scanning of Python dependencies.
- `bandit`: For static security analysis (optional).

Install the dependencies by running:

```bash
pip install -r requirements.txt
```

## Setup

### Groq API Key

To use the Groq API, you'll need an API key. Set it as an environment variable `GROQ_API_KEY`. If you're using GitHub Actions, you can store it in your repository's secrets.

### GitHub Token

A GitHub token is required to authenticate API requests. Set it as an environment variable `GIT_TOKEN`. You can also add it to the repository secrets.

### Set up GitHub Secrets

Add the following secrets to your GitHub repository:

- **GIT_TOKEN**: Your GitHub Personal Access Token (PAT).
- **GROQ_API_KEY**: Your Groq API key.

### Install Dependencies

Before running the bot, install the necessary dependencies by running:

```bash
pip install -r requirements.txt
```

## 🔍 Security Scanning Capabilities

The bot automatically scans for the following security vulnerabilities:

### Pattern-Based Detection
- **SQL Injection**: Detects unsafe SQL query construction
- **Cross-Site Scripting (XSS)**: Identifies potential XSS vulnerabilities
- **Path Traversal**: Finds directory traversal attack vectors
- **Hardcoded Secrets**: Detects exposed passwords, API keys, and tokens
- **Unsafe Deserialization**: Identifies dangerous deserialization patterns
- **Command Injection**: Detects shell injection vulnerabilities

### CVE Scanning
- **Dependency Analysis**: Automatically scans `requirements.txt`, `package.json`, and `Pipfile` changes
- **Known Vulnerabilities**: Checks against Safety database for active CVEs
- **Severity Assessment**: Provides severity ratings for identified vulnerabilities

### AI-Powered Reviews
- **Human-like Feedback**: Generates concise, actionable security reviews
- **Contextual Analysis**: Understands code context for better vulnerability assessment
- **Fix Suggestions**: Provides specific recommendations for security improvements

