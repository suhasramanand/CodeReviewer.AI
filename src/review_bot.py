import os
import re
import json
import requests
from groq import Groq
from typing import List, Dict, Optional
import subprocess
import tempfile

# Initialize Groq client
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
GIT_TOKEN = os.getenv("GIT_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")

# Security patterns to detect vulnerabilities
SECURITY_PATTERNS = {
    'sql_injection': [
        r'execute\s*\(\s*["\'].*%s.*["\']',
        r'cursor\.execute\s*\(\s*f["\'].*\{.*\}.*["\']',
        r'query\s*=\s*["\'].*\+.*["\']'
    ],
    'xss': [
        r'innerHTML\s*=',
        r'document\.write\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*["\']'
    ],
    'path_traversal': [
        r'\.\./',
        r'\.\.\\\\',
        r'open\s*\(\s*["\'].*\+.*["\']',
        r'file\s*=\s*["\'].*\+.*["\']'
    ],
    'hardcoded_secrets': [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']'
    ],
    'unsafe_deserialization': [
        r'pickle\.loads\s*\(',
        r'yaml\.load\s*\(',
        r'json\.loads\s*\(\s*request\.',
        r'eval\s*\('
    ],
    'command_injection': [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\(',
        r'os\.popen\s*\(',
        r'shell\s*=\s*True'
    ]
}

def get_latest_pr():
    """Fetch the latest pull request number from the repository."""
    headers = {
        "Authorization": f"Bearer {GIT_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CodeReviewer.AI-Bot"
    }
    # Use GITHUB_REPOSITORY environment variable if available, otherwise fallback to hardcoded value
    repo = GITHUB_REPOSITORY or "suhasramanand/CodeReviewer.AI"
    url = f"https://api.github.com/repos/{repo}/pulls?state=open"
    print(f"🔍 Checking for open PRs in {repo}...")
    print(f"🔑 Using token: {GIT_TOKEN[:10]}..." if GIT_TOKEN else "❌ No token provided")
    
    response = requests.get(url, headers=headers)
    print(f"📡 Response status: {response.status_code}")
    
    if response.status_code == 401:
        print("❌ Authentication failed. Please check:")
        print("   1. GIT_TOKEN secret is set correctly")
        print("   2. Token has 'repo' permissions")
        print("   3. Token is not expired")
        response.raise_for_status()
    
    response.raise_for_status()

    prs = response.json()
    if prs:
        print(f"✅ Found PR #{prs[0]['number']}: {prs[0]['title']}")
        return prs[0]['number']
    else:
        raise Exception("No open pull requests found.")

def get_diff(pr_number):
    """Fetch the pull request diff."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    # Use GITHUB_REPOSITORY environment variable if available, otherwise fallback to hardcoded value
    repo = GITHUB_REPOSITORY or "suhasramanand/CodeReviewer.AI"
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def check_cve_vulnerabilities(dependencies: List[str]) -> List[Dict]:
    """Check for known CVEs in dependencies using safety."""
    vulnerabilities = []
    try:
        # Create a temporary requirements file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(dependencies))
            temp_file = f.name
        
        # Run safety check
        result = subprocess.run(['safety', 'check', '-r', temp_file, '--json'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0 and result.stdout:
            try:
                safety_data = json.loads(result.stdout)
                for vuln in safety_data:
                    vulnerabilities.append({
                        'package': vuln.get('package_name', 'Unknown'),
                        'version': vuln.get('analyzed_version', 'Unknown'),
                        'cve': vuln.get('advisory', 'No CVE ID'),
                        'severity': vuln.get('severity', 'Unknown'),
                        'description': vuln.get('description', 'No description available')
                    })
            except json.JSONDecodeError:
                pass
        
        # Clean up temp file
        os.unlink(temp_file)
        
    except Exception as e:
        print(f"⚠️ CVE check failed: {e}")
    
    return vulnerabilities

def scan_for_security_vulnerabilities(code_content: str, file_name: str) -> List[Dict]:
    """Scan code for security vulnerabilities using pattern matching."""
    vulnerabilities = []
    
    for vuln_type, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = code_content[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    'type': vuln_type,
                    'line': line_num,
                    'code': match.group(0).strip(),
                    'severity': 'HIGH' if vuln_type in ['sql_injection', 'command_injection', 'unsafe_deserialization'] else 'MEDIUM',
                    'file': file_name
                })
    
    return vulnerabilities

def extract_dependencies_from_diff(patch: str) -> List[str]:
    """Extract dependencies from requirements.txt changes."""
    dependencies = []
    lines = patch.split('\n')
    for line in lines:
        if line.startswith('+') and not line.startswith('+++'):
            dep_line = line[1:].strip()
            if dep_line and not dep_line.startswith('#'):
                dependencies.append(dep_line)
    return dependencies

def generate_human_review(file_name: str, patch: str, vulnerabilities: List[Dict], cve_vulns: List[Dict]) -> str:
    """Generate human-like, concise security review using AI."""
    
    # Count vulnerabilities by severity
    high_vulns = [v for v in vulnerabilities if v['severity'] == 'HIGH']
    medium_vulns = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
    
    # Create vulnerability summary
    vuln_summary = ""
    if high_vulns:
        vuln_summary += f"🚨 **{len(high_vulns)} HIGH severity issues found**\n"
    if medium_vulns:
        vuln_summary += f"⚠️ **{len(medium_vulns)} MEDIUM severity issues found**\n"
    if cve_vulns:
        vuln_summary += f"🔍 **{len(cve_vulns)} known CVEs in dependencies**\n"
    
    if not vulnerabilities and not cve_vulns:
        vuln_summary = "✅ **No obvious security issues detected**\n"
    
    # Create detailed vulnerability list
    vuln_details = ""
    for vuln in vulnerabilities[:5]:  # Limit to top 5 for conciseness
        vuln_details += f"• **Line {vuln['line']}**: {vuln['type'].replace('_', ' ').title()} - `{vuln['code'][:50]}...`\n"
    
    for cve in cve_vulns[:3]:  # Limit to top 3 CVEs
        vuln_details += f"• **{cve['package']} {cve['version']}**: {cve['cve']} ({cve['severity']})\n"
    
    prompt = f"""You are a senior security engineer reviewing code changes. Be concise, human-like, and focus on security.

File: {file_name}
Code changes:
{patch[:2000]}...

Security scan results:
{vuln_summary}
{vuln_details}

Provide a brief, actionable security review (max 3-4 sentences). Focus on:
1. Critical security issues that need immediate attention
2. Specific fixes for vulnerabilities found
3. Best practices to implement

Be conversational but professional. Use emojis sparingly. Prioritize actionable feedback over general advice."""

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a senior security engineer. Provide concise, actionable security feedback. Be human-like and direct."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
            max_tokens=300,
            temperature=0.3
        )
        
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        return f"🔧 Security scan completed. {vuln_summary}{vuln_details}"

def review_code(file_diffs):
    """Analyze code changes with enhanced security focus."""
    comments = []
    
    for file in file_diffs:
        file_name = file["filename"]
        patch = file.get("patch", "")
        
        if not patch:
            continue
            
        print(f"🔍 Analyzing {file_name} for security issues...")
        
        # Extract added code for analysis
        added_lines = []
        for line in patch.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:])
        
        added_code = '\n'.join(added_lines)
        
        # Security vulnerability scanning
        vulnerabilities = scan_for_security_vulnerabilities(added_code, file_name)
        
        # CVE checking for dependencies
        cve_vulnerabilities = []
        if 'requirements.txt' in file_name or 'package.json' in file_name or 'Pipfile' in file_name:
            dependencies = extract_dependencies_from_diff(patch)
            if dependencies:
                cve_vulnerabilities = check_cve_vulnerabilities(dependencies)
        
        # Generate human-like review
        review = generate_human_review(file_name, patch, vulnerabilities, cve_vulnerabilities)
        
        # Format comment with security badge
        security_status = "🛡️ SECURE" if not vulnerabilities and not cve_vulnerabilities else "⚠️ SECURITY ISSUES"
        comment = f"## {security_status} - {file_name}\n\n{review}"
        
        comments.append(comment)
    
    return comments

def post_review(pr_number, comments):
    """Post security-focused comments back to the pull request."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    # Use GITHUB_REPOSITORY environment variable if available, otherwise fallback to hardcoded value
    repo = GITHUB_REPOSITORY or "suhasramanand/CodeReviewer.AI"
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    
    for comment in comments:
        payload = {"body": comment}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"✅ Posted security review comment")

if __name__ == "__main__":
    try:
        print("🛡️ Starting Security Code Review Bot...")
        
        # Try to get PR number from GitHub Actions context first
        pr_number = os.getenv("GITHUB_EVENT_NUMBER") or os.getenv("GITHUB_PR_NUMBER")
        if not pr_number:
            print("🔍 No GitHub context found, trying to fetch latest PR...")
            pr_number = get_latest_pr()
        else:
            print(f"📋 Using PR number from GitHub Actions context: {pr_number}")
        
        diffs = get_diff(pr_number)
        print(f"📁 Analyzing {len(diffs)} files...")
        
        review_comments = review_code(diffs)
        
        if review_comments:
            post_review(pr_number, review_comments)
            print(f"🎉 Security review completed for PR #{pr_number}")
        else:
            print("ℹ️ No files to review")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        raise
