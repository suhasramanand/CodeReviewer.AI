import os
import openai
import requests

# Initialize OpenAI API
openai.api_key = os.getenv("OPENAI_API_KEY")

# GitHub API details
GIT_TOKEN = os.getenv("GIT_TOKEN")
GITHUB_REPOSITORY = os.getenv("GIT_REPO")

def get_latest_pr():
    """Fetch the latest pull request number from the repository."""
    headers = {"Authorization": f"Bearer {GIT_TOKEN}"}
    url = f"https://api.github.com/repos/suhasramanand/CodeReviewer.AI/pulls?state=open"
    print(f"Requesting PRs from URL: {url}")  # Add debug log
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    # If there are open PRs, get the first one
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
    """Analyze code changes using OpenAI."""
    comments = []
    for file in file_diffs:
        file_name = file["filename"]
        patch = file.get("patch")
        if not patch:
            continue

        prompt = f"Review the following code changes in {file_name} and provide suggestions for improvement:\n{patch}"
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are a code review assistant."},
                      {"role": "user", "content": prompt}]
        )

        comments.append(f"**{file_name}:**\n{response['choices'][0]['message']['content']}")
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
    # Automatically fetch the latest PR number
    pr_number = get_latest_pr()
    
    # Fetch the diff for the latest PR
    diffs = get_diff(pr_number)
    
    # Review the code
    review_comments = review_code(diffs)
    
    # Post the review comments back to the PR
    post_review(pr_number, review_comments)