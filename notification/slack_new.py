from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.webhook import WebhookClient
import requests

class slackNotification:
    
    def __init__(self,token,channel):
        self.token = token
        self.channel = channel
    
    # Publish Message using OAUTH Token
    def pushSlackNotificationOAUTH(self,message):
        client = WebClient(token=self.token)
        try:
            response = client.chat_postMessage(channel=self.channel, text=message)
            print("Notification sent to the {} Channel".format(self.channel))
            return response
        except SlackApiError as slackErr:
            print("Error Sending Message:", slackErr)
    
    # Publish Message using WebHook URL
    def publishSlackNotificationWebHook(self,message):
        try:
            webhook = WebhookClient(self.token)
            webhook.send(text=message)
            print("Notification sent to the {} Channel".format(self.channel))
        except Exception as slackErr:
            print("Error Sending Message:", slackErr)

    def send_slack_notification(self,slackMessageBlock):
        # message = {
        #     "blocks": slackMessageBlock
        # }
        try:
            webhook = WebhookClient(self.token)
            print(slackMessageBlock)
            response = webhook.send(
                text="fallback",
                blocks=slackMessageBlock
            )
            if response.status_code == 200:
                print('Slack notification sent successfully!')
            else:
                print(f'Error sending Slack notification: {response.status_code} Error')
        except requests.exceptions.RequestException as e:
            print(f'Error sending Slack notification: {e}')
