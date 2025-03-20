import json
import requests
import datetime
from slack import slackNotification
import os

log_file = os.path.expanduser("dependabot.log")  # Ensure this matches

if not os.path.exists(log_file):
    raise FileNotFoundError(f"Log file not found: {os.path.abspath(log_file)}")

with open(log_file, "r") as f:
    data = f.read()
    print("Log File Content:")
    
now = datetime.datetime.now(datetime.UTC)

token=os.environ["DEPENDABOT_TEST"]

slackWrapper = slackNotification("https://hooks.slack.com/services/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","#monitoring")

def fetchRecentDependabotIssues(data, ecoSystem):
    #all_alerts = [alert for page in data for alert in page]  
    for res in data:
        #print(res)
        summary =res['security_advisory']['summary']

        print(summary)
        package_name = res['dependency']['package']['name']
        cve_id = res['security_advisory']['cve_id']
        severity = res['security_advisory']['severity']
        vuln_range = res["security_advisory"]['vulnerabilities'][0]['vulnerable_version_range']
        advisory_url = res["security_advisory"]['references'][0]['url']
        alert_url = res["html_url"]


        if package_name == ecoSystem:
          issueTime = datetime.datetime.strptime(res['created_at'],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
          time_diff = now - issueTime

          if time_diff.total_seconds() <= 300:
              slack_message = 	[
                                  {
                                    "type": "section",
                                    "text": {
                                      "type": "mrkdwn",
                                      "text": f"🚨 Detected a new Vulnerability: *<{alert_url}|{summary}>*"
                                    }
                                  },
                                  {
                                    "type": "section",
                                    "fields": [
                                      {
                                        "type": "mrkdwn",
                                        "text": f"*Package:*`{package_name}`"
                                      },
                                      {
                                        "type": "mrkdwn",
                                        "text": f"*CVE ID:*`{cve_id}`"
                                      },
                                      {
                                        "type": "mrkdwn",
                                        "text": f"*Severity:*`{severity.upper()}`"
                                      },
                                      {
                                        "type": "mrkdwn",
                                        "text": f"*Vulnerable Range:*`{vuln_range}`"
                                      },
                                      {
                                        "type": "mrkdwn",
                                        "text": f"*Detected at:*`{issueTime}`"
                                      }
                                    ]
                                  },
                                  {
                                    "type": "actions",
                                    "elements": [
                                      {
                                        "type": "button",
                                        "text": {
                                          "type": "plain_text",
                                          "emoji": bool("true"),
                                          "text": "More Info"
                                        },
                                        "style": "primary",
                                        "value": f"{advisory_url}"
                                      },
                                      {
                                        "type": "button",
                                        "text": {
                                          "type": "plain_text",
                                          "emoji": bool("true"),
                                          "text": "View GitHub Alert"
                                        },
                                        "style": "primary",
                                        "value": f"{alert_url}"
                                      }
                                    ]
                                  }
                                ]

              slackWrapper.send_slack_notification(json.dumps(slack_message))
          else:
              print("The timestamp is older than 5 minutes.")
              slackWrapper.publishSlackNotificationWebHook("The timestamp is older than 5 minutes.")


def filterParentJobDetails(log_file):
    with open(log_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            if 'Job definition:' in line:
                line = line.split(" Job definition: ")
                jobDefinition=json.loads(line[-1].strip()) \

    dependencies = jobDefinition["job"]["dependencies"]
    #print("Dependencies:", dependencies[0])

    return (dependencies[0])

headPipelinePackage = filterParentJobDetails(log_file)

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

    # Handle possible API failure
    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")
        break

    data = response.json()  # Parse response JSON

    # Check if the response is empty before appending
    if not data:  
        print("No more alerts, stopping.")
        break
    
    alerts.extend(data)  # Append to list
    page += 1

fetchRecentDependabotIssues(alerts,headPipelinePackage)
