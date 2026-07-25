# SeCoRA (Secure Code Review AI Agent) 🛡️

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> An AI-powered tool for detecting and remediating security vulnerabilities in codebases. This tool uses advanced language models to perform static analysis, vulnerability chaining, and provide actionable security recommendations.

## ✨ Features

- 🔍 AI-powered static analysis for security vulnerabilities
- 🎯 Detection of OWASP Top 10 and SANS Top 25 vulnerabilities
- ⛓️ Vulnerability chaining to identify interconnected risks (may not work perfectly)
- 🛠️ Detailed remediation suggestions with secure code examples
- 🐍 Support for Python code analysis (other languages need further testing)
- ⚡ Real-time analysis via API endpoints
- 📊 Comprehensive vulnerability reports with CVSS scoring

## 🚀 Prerequisites

- Python 3.12 or higher
- OpenAI API key
- Anthropic API key

## 💻 Installation

1. Clone the repository:

```bash
git clone https://github.com/nam091/VulnAgent_2.git
cd VulnAgent_2
```

2. Create a virtual environment and activate it:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip3 install -r requirements.txt
pip3 install -e .  # Install package in development mode
```

4. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your API keys
```

## 🔧 Usage

1. Start the server:

```bash
python3 src/main.py
# OR
secora
```

2. Access the API documentation at `http://localhost:8000/docs`

### 🌐 API Endpoints

- `POST /analyze/file`: Analyze a single file for vulnerabilities
- `POST /analyze/repository`: Analyze an entire git repository
- `GET /health`: Health check endpoint

### 📝 Example Usage

```python
import requests

# Analyze a single file
files = {'file': open('your_code.py', 'rb')}
response = requests.post('http://localhost:8000/analyze/file', files=files)
vulnerabilities = response.json()

# Analyze a repository
data = {
    'repository_url': 'https://github.com/username/repo',
    'branch': 'main',
    'scan_depth': 3
}
response = requests.post('http://localhost:8000/analyze/repository', json=data)
report = response.json()
```

## ⚙️ Configuration

Create a `.env` file with the following variables:

```
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
```

## ⚠️ NOTE

- This tool has been primarily tested with Python codebases. Support for other programming languages is under development and needs further testing.
- Currently tested and compatible with OpenAI models including GPT o1-mini, 4o and 4o-mini.

## 🔮 Future Improvements

- 🌍 Support for additional programming languages (Java, JavaScript, Go, etc.)
- 🤖 Integration with more AI models and providers
- 🤝 Integration with popular CI/CD platforms
- 📈 Enhanced reporting
- 🔍 Pull Request scanning with automated security reviews
- 💬 Inline code comments for PR feedback
