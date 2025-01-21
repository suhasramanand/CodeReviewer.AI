import os
import requests
from groq import Groq
groq_api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

GIT_TOKEN = os.getenv("GIT_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")

def get_latest_pr():
    """Fetch the latest pull request number from the repository."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    url = f"https://api.github.com/repos/suhasramanand/CodeReviewer.AI/pulls?state=open"
    print(f"Requesting PRs from URL: {url}")  # Add debug log
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    prs = response.json()
    if prs:
        return prs[0]['number']
    else:
        raise Exception("No open pull requests found.")

def get_diff(pr_number):
    """Fetch the pull request diff."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    url = f"https://api.github.com/repos/suhasramanand/CodeReviewer.AI/pulls/{pr_number}/files"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def review_code(file_diffs):
    """Analyze code changes using Groq's LLaMA model."""
    comments = []
    for file in file_diffs:
        file_name = file["filename"]
        patch = file.get("patch")
        if not patch:
            continue

        prompt = (
            f"Review the following code changes in the file '{file_name}':\n\n"
            f"{patch}\n\n"
            f"### Perform the following tasks:\n"
            f"1. Analyze the **time complexity** and **space complexity** of the functions or logic in the code.\n"
            f"2. Identify any **potential vulnerabilities**, such as:\n"
            f"   - Unvalidated input\n"
            f"   - API abuse risks\n"
            f"   - Hardcoded sensitive information\n"
            f"   - Improper error handling\n"
            f"3. Suggest improvements to **optimize performance** and **enhance security**.\n"
            f"4. Provide general feedback on code quality, readability, and maintainability."
        )


        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a professional code reviewer with expertise in performance optimization and secure coding practices."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile"
        )

        comments.append(f"**{file_name}:**\n{chat_completion.choices[0].message.content}")
    return comments

def post_review(pr_number, comments):
    """Post comments back to the pull request."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    url = f"https://api.github.com/repos/suhasramanand/CodeReviewer.AI/issues/{pr_number}/comments"
    for comment in comments:
        payload = {"body": comment}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()

if __name__ == "__main__":
    pr_number = get_latest_pr()
    
    diffs = get_diff(pr_number)
    
    review_comments = review_code(diffs)
    
    post_review(pr_number, review_comments)
