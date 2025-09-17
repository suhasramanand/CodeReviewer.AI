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

# Code quality and security patterns to detect issues
CODE_PATTERNS = {
    'security': {
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
    },
    'code_quality': {
        'long_functions': [
            r'def\s+\w+\([^)]*\):\s*$'
        ],
        'magic_numbers': [
            r'\b\d{3,}\b'
        ],
        'todo_comments': [
            r'#\s*(TODO|FIXME|HACK|XXX)',
            r'//\s*(TODO|FIXME|HACK|XXX)'
        ],
        'print_statements': [
            r'print\s*\(',
            r'console\.log\s*\('
        ],
        'empty_catches': [
            r'except\s*:.*pass',
            r'catch\s*\([^)]*\)\s*\{\s*\}'
        ],
        'duplicate_code': [
            r'copy.*paste',
            r'duplicate'
        ]
    },
    'performance': {
        'n_plus_one': [
            r'for\s+\w+\s+in\s+\w+:\s*\n.*\.query\(',
            r'for\s+\w+\s+in\s+\w+:\s*\n.*\.get\('
        ],
        'inefficient_loops': [
            r'for\s+\w+\s+in\s+range\(len\(',
            r'\.append\(.*\)\s*in\s+loop'
        ],
        'memory_leaks': [
            r'global\s+\w+',
            r'static\s+\w+'
        ]
    },
    'best_practices': {
        'missing_error_handling': [
            r'def\s+\w+\([^)]*\):\s*\n(?!.*try)',
            r'function\s+\w+\([^)]*\)\s*\{\s*(?!.*try)'
        ],
        'hardcoded_values': [
            r'localhost',
            r'127\.0\.0\.1',
            r'http://',
            r'https://'
        ],
        'missing_validation': [
            r'def\s+\w+\([^)]*\):\s*\n(?!.*if.*is.*None)',
            r'function\s+\w+\([^)]*\)\s*\{\s*(?!.*if.*===.*null)'
        ]
    }
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

def get_diff_from_github_api(pr_number):
    """Fetch the pull request diff using GitHub API."""
    headers = {
        "Authorization": f"Bearer {GIT_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CodeReviewer.AI-Bot"
    }
    # Use GITHUB_REPOSITORY environment variable if available, otherwise fallback to hardcoded value
    repo = GITHUB_REPOSITORY or "suhasramanand/CodeReviewer.AI"
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    print(f"📁 Fetching diff for PR #{pr_number}...")
    
    response = requests.get(url, headers=headers)
    print(f"📡 Response status: {response.status_code}")
    
    if response.status_code == 401:
        print("❌ Authentication failed when fetching diff. Please check:")
        print("   1. GIT_TOKEN secret is set correctly")
        print("   2. Token has 'repo' permissions")
        print("   3. Token is not expired")
        response.raise_for_status()
    
    response.raise_for_status()
    return response.json()

def get_diff_from_git():
    """Get diff using git command instead of GitHub API."""
    try:
        print("📁 Getting diff using git command...")
        # Get the diff between the current branch and the base branch
        result = subprocess.run(['git', 'diff', 'origin/main', 'HEAD'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            diff_content = result.stdout
            print(f"✅ Got diff content ({len(diff_content)} characters)")
            
            # Parse the diff into a format similar to GitHub API response
            files = []
            current_file = None
            
            for line in diff_content.split('\n'):
                if line.startswith('diff --git'):
                    if current_file:
                        files.append(current_file)
                    # Extract filename from diff header
                    parts = line.split()
                    if len(parts) >= 4:
                        filename = parts[3][2:]  # Remove 'b/' prefix
                        current_file = {
                            "filename": filename,
                            "patch": ""
                        }
                elif current_file and line.startswith(('+', '-', ' ')):
                    current_file["patch"] += line + "\n"
            
            if current_file:
                files.append(current_file)
            
            print(f"📋 Parsed {len(files)} files from git diff")
            return files
        else:
            print(f"❌ Git diff failed: {result.stderr}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting git diff: {e}")
        return []

def get_diff(pr_number):
    """Get diff using git command first, fallback to GitHub API."""
    # Try git command first (no authentication needed)
    files = get_diff_from_git()
    
    if files:
        return files
    
    print("🔄 Git diff failed, trying GitHub API...")
    return get_diff_from_github_api(pr_number)

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

def scan_for_code_issues(code_content: str, file_name: str) -> List[Dict]:
    """Scan code for security, quality, performance, and best practice issues."""
    issues = []
    
    for category, patterns in CODE_PATTERNS.items():
        for issue_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = code_content[:match.start()].count('\n') + 1
                    
                    # Determine severity based on category and type
                    if category == 'security':
                        severity = 'HIGH' if issue_type in ['sql_injection', 'command_injection', 'unsafe_deserialization'] else 'MEDIUM'
                    elif category == 'performance':
                        severity = 'MEDIUM'
                    elif category == 'code_quality':
                        severity = 'LOW' if issue_type in ['todo_comments', 'print_statements'] else 'MEDIUM'
                    else:  # best_practices
                        severity = 'LOW'
                    
                    issues.append({
                        'category': category,
                        'type': issue_type,
                        'line': line_num,
                        'code': match.group(0).strip(),
                        'severity': severity,
                        'file': file_name
                    })
    
    return issues

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

def generate_human_review(file_name: str, patch: str, issues: List[Dict], cve_vulns: List[Dict]) -> str:
    """Generate human-like, concise code review using AI."""
    
    # Count issues by severity and category
    high_issues = [i for i in issues if i['severity'] == 'HIGH']
    medium_issues = [i for i in issues if i['severity'] == 'MEDIUM']
    low_issues = [i for i in issues if i['severity'] == 'LOW']
    
    # Group by category
    security_issues = [i for i in issues if i['category'] == 'security']
    quality_issues = [i for i in issues if i['category'] == 'code_quality']
    performance_issues = [i for i in issues if i['category'] == 'performance']
    best_practice_issues = [i for i in issues if i['category'] == 'best_practices']
    
    # Create issue summary
    issue_summary = ""
    if high_issues:
        issue_summary += f"🚨 **{len(high_issues)} critical issues**\n"
    if medium_issues:
        issue_summary += f"⚠️ **{len(medium_issues)} issues**\n"
    if low_issues:
        issue_summary += f"💡 **{len(low_issues)} suggestions**\n"
    if cve_vulns:
        issue_summary += f"🔍 **{len(cve_vulns)} CVEs in dependencies**\n"
    
    if not issues and not cve_vulns:
        issue_summary = "✅ **All good**\n"
    
    # Create detailed issue list (top 3 most critical)
    issue_details = ""
    for issue in sorted(issues, key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x['severity']))[:3]:
        category_emoji = {'security': '🛡️', 'code_quality': '📝', 'performance': '⚡', 'best_practices': '✨'}
        emoji = category_emoji.get(issue['category'], '📋')
        issue_details += f"• {emoji} **Line {issue['line']}**: {issue['type'].replace('_', ' ').title()}\n"
    
    for cve in cve_vulns[:2]:  # Limit to top 2 CVEs
        issue_details += f"• 🔍 **{cve['package']}**: {cve['cve']}\n"
    
    prompt = f"""You are a senior engineer reviewing PRs. Be EXTREMELY concise and human-like.

File: {file_name}
Code changes:
{patch[:800]}...

Review results:
{issue_summary}
{issue_details}

Provide a VERY brief review:
- If no issues: Just say "Looks good" or "All clear" (2-3 words max)
- If issues: Mention only the most critical issue in 1-2 lines max
- Be conversational, not formal
- Focus on what matters most

Examples:
- "Looks good 👍"
- "All clear"
- "SQL injection on line 15 - use params"
- "Missing error handling"
- "Performance issue - N+1 query" """

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a senior engineer. Be EXTREMELY brief. If no issues, just say 'Looks good'. If issues, mention only the most critical problem in 1-2 lines."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
            max_tokens=80,
            temperature=0.3
        )
        
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        return f"🔧 Review completed. {issue_summary}{issue_details}"

def review_code(file_diffs):
    """Analyze code changes with comprehensive engineering review."""
    comments = []
    
    for file in file_diffs:
        file_name = file["filename"]
        patch = file.get("patch", "")
        
        if not patch:
            continue
            
        print(f"🔍 Reviewing {file_name}...")
        
        # Extract added code for analysis
        added_lines = []
        for line in patch.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:])
        
        added_code = '\n'.join(added_lines)
        
        # Comprehensive code analysis
        issues = scan_for_code_issues(added_code, file_name)
        
        # CVE checking for dependencies
        cve_vulnerabilities = []
        if 'requirements.txt' in file_name or 'package.json' in file_name or 'Pipfile' in file_name:
            dependencies = extract_dependencies_from_diff(patch)
            if dependencies:
                cve_vulnerabilities = check_cve_vulnerabilities(dependencies)
        
        # Generate human-like review
        review = generate_human_review(file_name, patch, issues, cve_vulnerabilities)
        
        # Format comment with status badge
        if not issues and not cve_vulnerabilities:
            status = "✅ GOOD"
        elif any(i['severity'] == 'HIGH' for i in issues):
            status = "🚨 CRITICAL"
        elif any(i['severity'] == 'MEDIUM' for i in issues):
            status = "⚠️ ISSUES"
        else:
            status = "💡 SUGGESTIONS"
            
        comment = f"## {status} - {file_name}\n\n{review}"
        
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
        print("👨‍💻 Starting Senior Engineer Code Review Bot...")
        
        # Try to get PR number from GitHub Actions context first
        pr_number = os.getenv("GITHUB_EVENT_NUMBER") or os.getenv("GITHUB_PR_NUMBER")
        if not pr_number:
            print("🔍 No GitHub context found, trying to fetch latest PR...")
            pr_number = get_latest_pr()
        else:
            print(f"📋 Using PR number from GitHub Actions context: {pr_number}")
        
        diffs = get_diff(pr_number)
        print(f"📁 Reviewing {len(diffs)} files...")
        
        review_comments = review_code(diffs)
        
        if review_comments:
            post_review(pr_number, review_comments)
            print(f"🎉 Code review completed for PR #{pr_number}")
        else:
            print("ℹ️ No files to review")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        raise
