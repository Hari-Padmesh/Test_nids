import logging
import os
import threading
import time

import requests
from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

logger = logging.getLogger("my-api.resend")

class ResendEmailNotifier:
    def __init__(self, api_key: str, recipient: str, sender: str):
        self.api_key = api_key
        self.recipient = recipient
        self.sender = sender
        self._last_sent = {}
        self._lock = threading.Lock()

    def notify(self, alert):
        # Limit repeat emails for the same alert type.
        now = time.monotonic()
        with self._lock:
            last = self._last_sent.get(alert.label, 0)
            if now - last < 60:
                return
            self._last_sent[alert.label] = now

        threading.Thread(
            target=self._send,
            args=(alert,),
            daemon=True,
        ).start()

    def _send(self, alert):
        body = (
            f"Project: my-api\n"
            f"Severity: {alert.severity.value}\n"
            f"Threat: {alert.label}\n"
            f"Confidence: {alert.confidence:.1%}\n"
            f"Time: {alert.timestamp}\n"
            f"Details: {alert.flow_summary}\n"
        )

        try:
            response = requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "from": self.sender,
                    "to": [self.recipient],
                    "subject": f"[NetGuard] {alert.severity.value}: {alert.label}",
                    "text": body,
                },
                timeout=15,
            )
            if response.status_code >= 400:
                logger.error(
                    "Resend API failed (%s): %s",
                    response.status_code,
                    response.text,
                )
        except Exception:
            logger.exception("Could not send alert through Resend")


app = FastAPI(title="My API")

guard = NetGuard(
    project_id="my-api",
    auth_username=os.environ["NETGUARD_AUTH_USERNAME"],
    auth_password=os.environ["NETGUARD_AUTH_PASSWORD"],
)

resend_key = os.getenv("RESEND_API_KEY")
if resend_key:
    recipient = os.getenv("NETGUARD_ALERT_EMAIL")
    if not recipient:
        raise RuntimeError("Set NETGUARD_ALERT_EMAIL in Render")

    guard.register_notifier(
        ResendEmailNotifier(
            api_key=resend_key,
            recipient=recipient,
            sender=os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev"),
        )
    )

setup_netguard(app, guard)


@app.get("/")
async def home():
    return {"message": "My API is running"}


@app.get("/items/{item_id}")
async def get_item(item_id: int):
    return {"item_id": item_id} 