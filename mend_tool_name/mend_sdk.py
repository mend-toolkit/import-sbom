import datetime
import http.client
import json
import logging
import requests


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
is_debug = logging.DEBUG if os.environ.get("DEBUG") in ['True', 'true', "1"] else logging.INFO

formatter = logging.Formatter('[%(asctime)s] %(levelname)5s %(message)s', "%Y-%m-%d %H:%M:%S")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
s_handler.setLevel(is_debug)
logger.addHandler(s_handler)
logger.propagate = False


class API():
    pass


class Agent():
    def _extract_url(url: str) -> str:
        url_ = url if url.startswith("https://") else f"https://{url}"
        url_ = url_.replace("http://", "")
        pos = url_.find("/", 8)  # Not using any suffix, just direct url
        return url_[0:pos] if pos > -1 else url_
    

    @classmethod
    def update_request(update_file, mend_server, update_type="OVERRIDE"):
        with open(update_file, 'r') as f_update:
            update = json.load(f_update)
        if not update:
            return None
        
        ts = round(datetime.datetime.now().timestamp())
        ret = None
        try:
            # conn = http.client.HTTPSConnection(f"{Agent._extract_url(mend_server)[8:]}")
            with http.client.HTTPSConnection(f"{Agent._extract_url(mend_server)[8:]}") as conn:
                json_prj = json.dumps(update['projects'])
                
                payload_obj = {
                    "type": "UPDATE",
                    "updateType": update_type,
                    "agent": "fs-agent",
                    "agentVersion": "1.0",
                    "token": WS_APIKEY,
                    "userKey": WS_USERKEY,
                    "product": WS_PRODUCTNAME,
                    "timeStamp": ts,
                    "diff": json_prj
                }
                payload = '&'.join(f'{k}={v}' for k, v in payload_obj.items())
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                conn.request("POST", "/agent", payload, headers)
                data = json.loads(conn.getresponse().read())
                data_json = json.loads(data["data"])
                data_json["product"] = update.get("product")
                if data['status'] == 1:
                    ret = data_json
                else:
                    raise Exception(f'Mend update request failed: {data["message"]} ({data["data"]})')
                # conn.close()
        except Exception as err:
            logger.error(f"Upload failed: {err}")
        return ret
