import argparse
import datetime
import inspect
import json
import logging
import os
import sys
import http.client
import re
import hashlib

from mend_tool_name._version import __version__, __tool_name__, __description__
from mend_tool_name.const import aliases, varenvs
from mend_tool_name.mend_sdk import API

logger = logging.getLogger(__tool_name__)
logger.setLevel(logging.DEBUG)
is_debug = logging.DEBUG if os.environ.get("DEBUG") in ['True', 'true', "1"] else logging.INFO

formatter = logging.Formatter('[%(asctime)s] %(levelname)5s %(message)s', "%Y-%m-%d %H:%M:%S")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
s_handler.setLevel(is_debug)
logger.addHandler(s_handler)
logger.propagate = False

APP_TITLE = "Mend TOOL NAME"


def try_or_error(supplier, msg):
    try:
        return supplier()
    except:
        return msg


def fn():
    fn_stack = inspect.stack()[1]
    return f'{fn_stack.function}:{fn_stack.lineno}'


def log_obj_props(obj, obj_title=""):
    masked_props = ["ws_user_key", "user_key"]
    prop_list = [obj_title] if obj_title else []
    try:
        obj_dict = obj if obj is dict else obj.__dict__
        for k in obj_dict:
            v = "******" if k in masked_props else obj_dict[k]
            prop_list.append(f'{k}={v}')
        logger.debug("\n\t".join(prop_list))
    except Exception as err:
        logger.error(f'[{fn()}] Failed: {err}')


def parse_args():
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument(*aliases.get_aliases_str("userkey"), help="Mend user key", dest='ws_user_key',
                        default=varenvs.get_env("wsuserkey"), required=not varenvs.get_env("wsuserkey"))
    parser.add_argument(*aliases.get_aliases_str("apikey"), help="Mend API key", dest='ws_token',
                        default=varenvs.get_env("wsapikey"), required=not varenvs.get_env("wsapikey"))
    parser.add_argument(*aliases.get_aliases_str("projectkey"), help="Mend product/project scope", dest='scope_token',
                        default=varenvs.get_env("wsscope"))
    parser.add_argument(*aliases.get_aliases_str("sbom"), help="SBOM Report for upload (*.json|*.csv)", dest='sbom',
                        required=True, default=os.environ.get("SBOM", ''))
    parser.add_argument('--updateType', help="Update type", dest='update_type',
                        default=os.environ.get("WS_UPDATETYPE", 'OVERRIDE'))
    parser.add_argument(*aliases.get_aliases_str("output"), help="Output directory", dest='out_dir',
                        default=os.getcwd())
    parser.add_argument(*aliases.get_aliases_str("url"), help="Mend server URL", dest='ws_url',
                        default=varenvs.get_env("wsurl"), required=not varenvs.get_env("wsurl"))
    parser.add_argument('--offline', help="Create update request file without uploading", dest='offline',
                        default=os.environ.get("WS_OFFLINE", 'false'))
    arguments = parser.parse_args()

    return arguments


def upload_to_mend(upload):
    ts = round(datetime.datetime.now().timestamp())
    ret = None
    try:
        conn = http.client.HTTPSConnection(f"{extract_url(args.ws_url)[8:]}")
        json_prj = json.dumps(upload['projects'])  # API understands just JSON Array type, not simple List
        upload_projects = [proj["coordinates"]["artifactId"] for proj in upload["projects"]]
        if len(upload_projects) > 1:
            proj_txt = "\n  ".join(upload_projects)
            logger.debug(f'[{fn()}] Uploading projects:\n  {proj_txt}')
        else:
            logger.debug(f'[{fn()}] Uploading project:  {upload_projects[0]}')

        payload = f"type=UPDATE&updateType={args.update_type}&agent=fs-agent&agentVersion=1.0&token={args.ws_token}&" \
                  f"userKey={args.ws_user_key}&product={args.ws_product}&timeStamp={ts}&diff={json_prj}"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        conn.request("POST", "/agent", payload, headers)
        data = json.loads(conn.getresponse().read())
        data_json = json.loads(data["data"])
        data_json["product"] = upload.get("product")
        logger.debug(f'[{fn()}] Response:\n{json.dumps(data_json, indent=2)}')
        if data['status'] == 1:
            ret = data_json
        else:
            logger.error(f"Mend update request failed: {data['message']} ({data['data']})")
        conn.close()
    except Exception as err:
        logger.error(f"Upload failed: {err}")
    return ret


def extract_url(url: str) -> str:
    url_ = url if url.startswith("https://") else f"https://{url}"
    url_ = url_.replace("http://", "")
    pos = url_.find("/", 8)  # Not using any suffix, just direct url
    return url_[0:pos] if pos > -1 else url_


def analyse_scope(scope: str):
    scope_layers = scope.split("//") if scope else [""]
    logger.debug(f'[{fn()}] Scope layers: {scope_layers}')
    len_ = len(scope_layers)
    prd_name = DFLT_PRD_NAME
    if len_ == 3:  # Provided Organization//Product//Project
        prd_name = scope_layers[1]
        prj_name = scope_layers[2]
    elif len_ == 2:  # Provided Product//Project
        prd_name = scope_layers[0]
        prj_name = scope_layers[1]
    else:
        prj_name = scope_layers[0]

    args.ws_product = prd_name
    logger.debug(f'[{fn()}] Product name: {prd_name}')

    if prj_name:
        logger.debug(f'[{fn()}] Attempting to resolve project scope')
        try:
            rt = WS.call_ws_api(self=args.ws_conn, request_type="getProjectVitals",
                                kv_dict={"projectToken": prj_name})
            args.scope_token = rt['projectVitals'][0]['token']
            args.ws_product = ""
            logger.debug(f'[{fn()}] Project token: {args.scope_token}')
        except:
            args.scope_token = ""
    args.ws_project = prj_name
    logger.debug(f'[{fn()}] Project name: {args.ws_project}')


def main():
    global output_json
    global args
    output_json = {}

    hdr_title = f'{APP_TITLE} {__version__}'
    hdr = f'\n{len(hdr_title)*"="}\n{hdr_title}\n{len(hdr_title)*"="}'
    logger.info(hdr)

    try:
        args = parse_args()
        log_obj_props(args, "Configuration:")

        args.ws_conn = web.WSApp(url=f"{extract_url(args.ws_url)}",
                                 user_key=args.ws_user_key,
                                 token=args.ws_token,
                                 tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__))
        log_obj_props(args.ws_conn, "WSApp connection:")

        if not os.path.isfile(args.sbom):
            logger.error(f'[{fn()}] Input file does not exist: {args.out_dir}')
            exit(-1)

        if not os.path.isdir(args.out_dir):
            logger.info(f'[{fn()}] Creating output directory: {args.out_dir}')
            try:
                os.mkdir(args.out_dir)
            except Exception as err:
                logger.error(f'[{fn()}] {err}')
                exit(-1)

        logger.info(f'[{fn()}] Generating update request')
        full_path = os.path.join(args.out_dir, UPDATE_REQUEST_FILE)

        logger.debug(f'[{fn()}] Resolving project scope')
        analyse_scope(args.scope_token)

        logger.debug(f'[{fn()}] Generating json body')
        output_json = create_body(args)

        logger.debug(f'[{fn()}] Creating update request file')
        with open(full_path, 'w') as outfile:
            json.dump(output_json, outfile, indent=4)
        logger.info(f'[{fn()}] Update request created successfully: {full_path}')
    except Exception as err:
        logger.error(f'[{fn()}] Failed to create update request file: {err}')
        exit(-1)

    try:
        if args.offline.lower() == "false":
            logger.info(f'[{fn()}] Uploading data to Mend')
            res_upload = upload_to_mend(output_json)
            if res_upload:
                proj_ids = res_upload["projectNamesToIds"]
                proj_updated = [f'{p} ({args.ws_url}{PROJ_URL}{proj_ids[p]})' for p in res_upload["updatedProjects"]]
                proj_created = [f'{p} ({args.ws_url}{PROJ_URL}{proj_ids[p]})' for p in res_upload["createdProjects"]]
                res_txt = f'Upload successful\n  Organization: {res_upload["organization"]}'
                if res_upload["product"]:
                    res_txt = f'{res_txt}\n  Product: {res_upload["product"]}'
                if len(proj_created) > 1:
                    res_txt = f'{res_txt}\n  Projects created:'
                    for pj in proj_created:
                        res_txt = f'{res_txt}\n    {pj}'
                elif len(proj_created) > 0:
                    res_txt = f'{res_txt}\n  Project created: {proj_created[0]}'
                if len(proj_updated) > 1:
                    res_txt = f'{res_txt}\n  Projects updated:'
                    for pj in proj_updated:
                        res_txt = f'{res_txt}\n    {pj}'
                elif len(proj_updated) > 0:
                    res_txt = f'{res_txt}\n  Project updated: {proj_updated[0]}'
                logger.info(f'[{fn()}] {res_txt}')
                logger.debug(f'[{fn()}] Request token: {res_upload["requestToken"]}')

    except Exception as err:
        logger.error(f"Upload failed: {err}")


if __name__ == '__main__':
    sys.exit(main())
