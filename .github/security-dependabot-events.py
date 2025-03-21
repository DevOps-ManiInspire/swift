import json
import requests
import datetime
from slack import slackNotification
import os

now = datetime.datetime.now(datetime.UTC)

githubToken = os.environ["githubToken"]
slackWebHookURL = os.environ["slackWebHookURL"]
codeCommitter = os.environ["codeCommitter"]
commitSHA = os.environ["commitSHA"]
repoName = os.environ["repoName"]
branchName = os.environ["branchName"]
scanWaitTime = 100  # In Seconds
slackChannelName = "#monitoring"

slackWrapper = slackNotification(slackWebHookURL, slackChannelName)

def fetchRecentDependabotIssues(packageData):
    for packageDetail in packageData:
        # Metadata from the alert
        summary = packageDetail["security_advisory"]["summary"]
        alertDescription = packageDetail["security_advisory"]["description"]
        alertPackageName = packageDetail["dependency"]["package"]["name"]
        alertCVEId = packageDetail["security_advisory"]["cve_id"]
        alertSeverity = packageDetail["security_advisory"]["severity"]
        alertPackageVulRange = packageDetail["security_advisory"]["vulnerabilities"][0][
            "vulnerable_version_range"
        ]
        alertAdvisoryURL = packageDetail["security_advisory"]["references"][0]["url"]
        alertURL = packageDetail["html_url"]
        issueTime = datetime.datetime.strptime(
            packageDetail["updated_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=datetime.timezone.utc)
        AlertTimeDiff = now - issueTime

        if packageDetail["state"] == "open":
            print(f"Scanning {alertPackageName}")

            if AlertTimeDiff.total_seconds() <= scanWaitTime:
                print(
                    f"New Dependabot Alert is detected for package {alertPackageName}"
                )
                slackMessageData = [
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"⚠️ *New Vulnerability Detected*\n\n*Repository:* `{repoName}@{branchName}`\n\n*Summary:* *<{alertURL}|{summary}>*\n\n*Vulnerability Report:* \n\t{alertDescription}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Package:* *`{alertPackageName}`*",
                        },
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Additional Details:*"},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"- *CVE ID:* `{alertCVEId}`\n- *Severity:* `{alertSeverity}`\n- *Vulnerable Range:* `{alertPackageVulRange}`\n- *Detected at:* `{issueTime}`\n- *Committer:* `{codeCommitter}`\n- *Commit SHA:* `{commitSHA}`",
                        },
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "emoji": bool("true"),
                                    "text": "More Info",
                                },
                                "style": "primary",
                                "url": f"{alertAdvisoryURL}",
                            }
                        ],
                    },
                    {"type": "divider"},
                ]

                slackWrapper.send_slack_notification(json.dumps(slackMessageData))
            else:
                print(
                    f"The timestamp is older than {scanWaitTime} seconds. skipping...!"
                )

requestPage = 1
alertList = []

while True:
    print(f"Fetching RequestPage:{requestPage}")

    response = requests.get(
        f"https://api.github.com/repos/{repoName}/dependabot/alerts?page={requestPage}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {githubToken}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")
        break

    packageData = response.json()

    if not packageData:
        print("No more alerts, stopping...!")
        break

    alertList.extend(packageData)
    requestPage += 1

fetchRecentDependabotIssues(alertList)
