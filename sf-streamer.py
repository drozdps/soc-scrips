
import time
import json
import logging
import requests
import urllib.parse

# --- CONFIGURATION ---

CLIENT_ID = 'MOCK'
CLIENT_SECRET = 'MOCK'
TOKEN_URL = 'MOCK/services/oauth2/token'

CHANNELS = [
    "/event/LoginEventStream",
    "/event/ApiAnomalyEvent",
    "/event/CredentialStuffingEvent",
    "/event/ReportAnomalyEvent",
    "/event/SessionHijackingEvent",
    "/event/UriEventStream",
    "/event/PermissionSetEvent",
    "/event/LoginAsEventStream",
    "/event/LightningUriEventStream",
    "/event/ApiEventStream",
    "/event/BulkApiResultEvent",
    "/event/FileEvent",
    "/event/ListViewEventStream"

]

LOG_FILE = '/var/log/salesforce_stream.json'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='/var/log/sf_streamer_debug.log'
)

def get_salesforce_token():
    logging.info("Requesting Access Token via Client Credentials...")
    payload = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    try:
        resp = requests.post(TOKEN_URL, data=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logging.error(f"Auth failed: {e}")
        raise

def stream_events():
    msg_id = 1
    
    # Create a Persistent Session (Handles Cookies & Keep-Alive automatically)
    session = requests.Session()
    
    while True:
        try:
            # 1. Authenticate
            token_data = get_salesforce_token()
            access_token = token_data['access_token']
            instance_url = token_data['instance_url']
            
            # 2. Setup Headers for the Session
            # These will be sent with EVERY request automatically
            session.headers.update({
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
            
            endpoint = f"{instance_url}/cometd/58.0"
            
            # --- STEP A: HANDSHAKE ---
            logging.info("Step 1: Handshake...")
            handshake_payload = {
                "id": str(msg_id),
                "channel": "/meta/handshake",
                "version": "1.0",
                "supportedConnectionTypes": ["long-polling"]
            }
            msg_id += 1
            
            resp = session.post(endpoint, json=handshake_payload, timeout=30)
            resp_data = resp.json()
            if isinstance(resp_data, list): resp_data = resp_data[0]
            
            if not resp_data.get("successful"):
                raise Exception(f"Handshake Failed: {json.dumps(resp_data)}")
            
            client_id = resp_data["clientId"]
            logging.info(f"Handshake successful. Client ID: {client_id}")
            
            # --- STEP B: BATCH SUBSCRIBE ---
            logging.info("Step 2: Batch Subscribing...")
            batch_payload = []
            for channel in CHANNELS:
                sub_req = {
                    "id": str(msg_id),
                    "channel": "/meta/subscribe",
                    "clientId": client_id,
                    "subscription": channel,
                    "ext": {
                        "replay": {channel: -1}
                    }
                }
                batch_payload.append(sub_req)
                msg_id += 1
            
            resp = session.post(endpoint, json=batch_payload, timeout=30)
            sub_responses = resp.json()
            if not isinstance(sub_responses, list): sub_responses = [sub_responses]
            
            failure_count = 0
            for sub_resp in sub_responses:
                if not sub_resp.get("successful"):
                    logging.error(f"Sub failed: {json.dumps(sub_resp)}")
                    failure_count += 1
            
            if failure_count == len(CHANNELS):
                raise Exception("All subscriptions failed. Re-handshaking.")
            
            logging.info(f"Subscribed to {len(CHANNELS) - failure_count} channels.")

            # --- STEP C: CONNECT LOOP ---
            logging.info("Step 3: Entering Long-Polling Loop...")
            while True:
                connect_payload = {
                    "id": str(msg_id),
                    "channel": "/meta/connect",
                    "clientId": client_id,
                    "connectionType": "long-polling"
                }
                msg_id += 1
                
                # Salesforce timeout is 110s. Requests timeout set to 120s.
                try:
                    resp = session.post(endpoint, json=connect_payload, timeout=120)
                    logging.info(f'response: {resp}')
                    response_list = resp.json()
                    if not isinstance(response_list, list): response_list = [response_list]

                    for message in response_list:
                        channel = message.get("channel")

                        # Handle Meta Messages
                        if channel == "/meta/connect":
                            if not message.get("successful"):
                                logging.error(f"Connect rejected: {json.dumps(message)}")
                                advice = message.get("advice", {})
                                if advice.get("reconnect") == "handshake":
                                    raise Exception("Re-handshake required.")
                                time.sleep(2)
                                continue
                            continue
                        
                        # Handle Real Data
                        if not channel.startswith("/meta/"):
                            data = message.get("data", {}).get("payload", {})
                            
                            log_entry = {
                                "wazuh_tag": "salesforce_stream",
                                "event_type": channel,
                                "payload": data
                            }
                            
                            with open(LOG_FILE, 'a') as f:
                                f.write(json.dumps(log_entry) + '\n')
                                f.flush()
                                
                except requests.exceptions.Timeout:
                    # Timeout is normal for long-polling. Just loop again.
                    continue

        except Exception as e:
            logging.error(f"Streamer Error: {e}")
            logging.info("Reconnecting in 15 seconds...")
            # Reset session to clear bad cookies/state
            session = requests.Session()
            time.sleep(15)

if __name__ == "__main__":
    try:
        # Create log file if it doesn't exist
        open(LOG_FILE, 'a').close()
        stream_events()
    except KeyboardInterrupt:
        logging.info("Stopping streamer...")
