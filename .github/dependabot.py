import json
import requests
import datetime
from slack import slackNotification
import os

now = datetime.datetime.now(datetime.UTC)

token=os.environ["DEPENDABOT_TEST"]
slacktoken=os.environ["SLACK"]
codeCommitter=os.environ["codeCommitter"]
commitSHA=os.environ["commitSHA"]
branchName=os.environ["branchName"]
repoName=os.environ["repoName"]

slackWrapper = slackNotification(slacktoken,"#monitoring")

def fetchRecentDependabotIssues(data):
    for res in data:
        summary =res['security_advisory']['summary']
        package_name = res['dependency']['package']['name']
        cve_id = res['security_advisory']['cve_id']
        severity = res['security_advisory']['severity']
        vuln_range = res["security_advisory"]['vulnerabilities'][0]['vulnerable_version_range']
        advisory_url = res["security_advisory"]['references'][0]['url']
        alert_url = res["html_url"]
        issueTime = datetime.datetime.strptime(res['updated_at'],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        time_diff = now - issueTime

        if res['state'] == "open":
          print(res)
          print(now)
          print(f"issueTime: {issueTime}")
          
          print(f"UpdatedAt: {res['updated_at']}")
          print(f"CreatedAt: {res['created_at']}")
          print(time_diff.total_seconds)
          print(package_name)
          if time_diff.total_seconds() <= 100:
              slack_message = [{
                    "type": "home",
                    "blocks": [
                      {
                        "type": "divider"
                      },
                      {
                        "type": "section",
                        "text": {
                          "type": "mrkdwn",
                          "text": f"⚠️ *New Vulnerability Detected*\n\n*Summary:* {summary}\n\n*Repository:* `{repoName}@{branchName}`\n\n*<{alert_url}|{summary}>*"
                        }
                      },
                      {
                        "type": "section",
                        "text": {
                          "type": "mrkdwn",
                          "text": f"*Package:* *`{package_name}`*"
                        }
                      },
                      {
                        "type": "section",
                        "text": {
                          "type": "mrkdwn",
                          "text": "*Additional Details:*"
                        }
                      },
                      {
                        "type": "section",
                        "text": {
                          "type": "mrkdwn",
                          "text": f"- *CVE ID:* `{cve_id}`\n- *Severity:* `{severity}`\n- *Vulnerable Range:* `{vuln_range}`\n- *Detected at:* `{issue_time}`\n- *Committer:* `{codeCommitter}`\n- *Commit SHA:* `{commitSHA}`"
                        }
                      },
                      {
                        "type": "actions",
                        "elements": [
                          {
                            "type": "button",
                            "text": {
                              "type": "plain_text",
                              "emoji": true,
                              "text": "More Info"
                            },
                            "style": "primary",
                            "url": f"{advisory_url}"
                          }
                        ]
                      },
                      {
                        "type": "divider"
                      }
                    ]
                  }]

              slackWrapper.send_slack_notification(json.dumps(slack_message))
          else:
              print("The timestamp is older than 5 minutes.")
              #slackWrapper.publishSlackNotificationWebHook("The timestamp is older than 5 minutes.")


def filterParentJobDetails(log_file):
    with open(log_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            if 'Job definition:' in line:
                line = line.split(" Job definition: ")
                jobDefinition=json.loads(line[-1].strip()) \

    dependencies = jobDefinition["job"]["dependencies"]

    return (dependencies[0])

page=1
alerts = []

while True:
    print(f"Fetching page {page}...")

    response = requests.get(
        f"https://api.github.com/repos/DevOps-ManiInspire/swift/dependabot/alerts?page={page}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")
        break

    data = response.json()

    if not data:  
        print("No more alerts, stopping.")
        break
    
    alerts.extend(data)
    page += 1

fetchRecentDependabotIssues(alerts)
