import argparse
import csv
import datetime
import inspect
import json
import logging
import os
import sys
import http.client
import re
import hashlib
from ws_sdk import web, WS

from mend_import_sbom._version import __version__, __tool_name__, __description__
from mend_import_sbom.import_const import SHA1CalcType, aliases, varenvs

logger = logging.getLogger(__tool_name__)
logger.setLevel(logging.DEBUG)
is_debug = logging.DEBUG if os.environ.get("DEBUG") in ['True', 'true', "1"] else logging.INFO

formatter = logging.Formatter('[%(asctime)s] %(levelname)5s %(message)s', "%Y-%m-%d %H:%M:%S")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
s_handler.setLevel(is_debug)
logger.addHandler(s_handler)
logger.propagate = False

APP_TITLE = "Mend SBOM Importer"
DFLT_PRD_NAME = "Mend-Imports"
UPDATE_REQUEST_FILE = "update-request.txt"
PROJ_URL = '/Wss/WSS.html#!project;id='  # f'{WS_WSS_URL}/Wss/WSS.html#!project;id={PROJECT_ID}'


def try_or_error(supplier, msg):
    try:
        return supplier()
    except:
        return msg


def fn():
    fn_stack = inspect.stack()[1]
    return f'{fn_stack.function}:{fn_stack.lineno}'


def pn():
    pn_stack = inspect.stack()[2]
    return f'{pn_stack.function}:{pn_stack.lineno}'


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


def check_el_inlist(name: str) -> bool:  # Don't need to do this check now, might be needed in the future
    res = False
    for rel in relations:
        for key, value in rel.items():
            if 'SPDXRef-PACKAGE-' + name == value:
                res = True
                break
    return res


def get_element_by_spdxid(spdx: str) -> dict:
    out_el = {}
    for el_ in pkgs:
        if el_["SPDXID"] == spdx:
            sha1 = try_or_error(lambda: f"{el_['checksums'][0]['checksumValue']}", '')
            chld = try_or_error(lambda: el_['children'], [])
            try:
                out_el = {
                    "artifactId": f"{el_['packageFileName']}",
                    "version": f"{try_or_error(lambda: el_['versionInfo'], '')}",
                    "sha1": sha1,
                    "systemPath": "",
                    "optional": False,
                    "filename": f"{el_['packageFileName']}",
                    "checksums": {
                        "SHA1": sha1
                    },
                    "dependencyFile": "",
                    "children": chld
                }
            except:
                pass
            break
    return out_el


def add_child(element: dict) -> dict:  # recursion for adding children
    new_el = element
    name = element['artifactId']
    for rel in relations:
        for key, value in rel.items():
            if key == 'SPDXRef-PACKAGE-' + name:
                chld_el = get_element_by_spdxid(value)
                try:
                    new_el['children'].append(chld_el)
                except:
                    new_el['children'] = [chld_el]
                if not chld_el['artifactId'] in added_el:
                    added_el.append(chld_el['artifactId'])
                    add_child(chld_el)
    return new_el


def csv_to_json(csv_file):
    data = {}
    dep = []
    count = 0
    try:
        logger.debug(f'[{fn()}] Reading CSV file: {csv_file}')
        with open(csv_file, encoding='utf-8') as csvf:
            csv_reader = csv.DictReader(csvf)
            for rows in csv_reader:
                key = count
                data[key] = rows
                count += 1

        json_ = json.loads(json.dumps(data, indent=4))
        for el_ in json_:
            pck = {
                "name": json_[el_]["name"],
                "licenseConcluded": json_[el_]["licenseConcluded"],
                "licenseInfoFromFiles": json_[el_]["licenseInfoFromFiles"],
                "licenseDeclared": json_[el_]["licenseDeclared"],
                "copyrightText": json_[el_]["copyrightText"],
                "versionInfo": json_[el_]["versionInfo"],
                "packageFileName": json_[el_]["packageFileName"],
                "supplier": json_[el_]["supplier"],
                "originator": json_[el_]["originator"],
                "homepage": json_[el_]["homepage"],
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA1", "checksumValue": json_[el_]["sha1"]}]
            }
            dep.append(pck)
    except Exception as err:
        logger.error(f'[{fn()}] Failed to convert CSV to JSON: {err}')

    return dep


def create_body(args):
    def create_add_sha1(langtype=""):  # maybe we will need to calculate additional sha1 later
        logger.debug(f'[{fn()}] langtype={langtype}')
        pkg_str = ""
        try:
            for ext_ref in package['externalRefs']:
                if ext_ref['referenceCategory'] == "PACKAGE_MANAGER":
                    pkgname = re.search(r"pkg:(.*?)/", ext_ref['referenceLocator'], flags=re.DOTALL).group(1).strip()
                    lang_type = SHA1CalcType.get_package_type(f_t=pkgname)
                    if lang_type.lower_case == "y":
                        pkg_str = f"{package['name'].lower()}_{package['versionInfo'].lower()}_{lang_type.language}"
                    else:
                        pkg_str = f"{package['name']}_{package['versionInfo']}_{lang_type.language}"
                    break
        except Exception as err:
            if langtype == "":
                return ""
            else:
                if SHA1CalcType.get_package_data(lng=langtype) == "y":
                    pkg_str = f"{package['name'].lower()}_{package['versionInfo'].lower()}_{langtype}"
                else:
                    pkg_str = f"{package['name']}_{package['versionInfo']}_{langtype}"
        return hashlib.sha1(pkg_str.encode("utf-8")).hexdigest()

    def get_pkg_parent(pkg_child: str):  # Will be needed for uploading source files
        logger.debug(f'[{fn()}] pkg_child={pkg_child}')
        res = ""
        try:
            rels = sbom["relationships"]
            for rel_ in rels:
                if rel_["relationshipType"] == "DYNAMIC_LINK" and rel_["relatedSpdxElement"] == pkg_child:
                    res = rel_["spdxElementId"]
                    break
        except:
            pass
        return res

    def search_lib_by_name(lib_name, lib_ver, lib_type):
        logger.debug(f'[{fn()}] Searching library: lib_name={lib_name}, lib_ver={lib_ver}, lib_type={lib_type}')
        sha1 = lname = ""
        error_code = 0
        error_msg = ""
        try:
            lib_lst = web.WS.call_ws_api(self=args.ws_conn, request_type="getBasicLibraryInfo",
                                         kv_dict={"libraryName": lib_name, "libraryVersion": lib_ver,
                                                  "libraryType": lib_type})
            for lib_ in lib_lst["librariesInformation"]:
                sha1 = try_or_error(lambda: lib_["sha1"], '')
                lname = try_or_error(lambda: lib_["artifactId"], '')
                break
        except Exception as err:
            error_code = json.loads(err.message[err.message.index("Error:")+6:])["errorCode"]  # Getting result as string, need to parse it
            error_msg = json.loads(err.message[err.message.index("Error:")+6:])["errorMessage"]
        logger.debug(f'[{fn()}] Result: sha1={sha1}, lname={lname}, error_code={error_code}, error_msg={error_msg}')
        return sha1, lname, error_code, error_msg

    ts = round(datetime.datetime.now().timestamp())
    global relations
    global pkgs
    global added_el
    global sbom
    relations = []
    added_el = []
    dep = []
    PrjID = args.ws_project if (not args.scope_token) else args.scope_token
    logger.debug(f'[{fn()}] ts={ts}, PrjID={PrjID}')

    try:
        if os.path.splitext(args.sbom)[1] == ".csv":
            logger.debug(f'[{fn()}] Parsing CSV file: {args.sbom}')
            sbom = csv_to_json(args.sbom)
        else:
            logger.debug(f'[{fn()}] Parsing JSON file: {args.sbom}')
            with open(args.sbom, "r", encoding="utf-8") as f:
                sbom = json.load(f)
            PrjID = try_or_error(lambda: sbom["name"], '') if (not PrjID) else PrjID
            logger.debug(f'[{fn()}] PrjID: {PrjID}')
    except Exception as err:
        logger.error(f'[{fn()}] Unable to parse input file: {err}')
        exit(-1)

    if PrjID == '' or PrjID is None:
        logger.error(f'[{fn()}] Scope must include either project name or project token')
        exit(-1)

    try:
        logger.debug(f'[{fn()}] Resolving dependency relationships')
        for rel_ in sbom["relationships"]:
            if rel_['relationshipType'] == "DEPENDS_ON":
                relations.append({rel_['spdxElementId']: rel_['relatedSpdxElement']})
    except AttributeError as err_a:
        logger.debug(f'[{fn()}] "relationships" block not found, skipping')

    pkgs = try_or_error(lambda: sbom["packages"], sbom)  # from JSON or from CSV
    logger.debug(f'[{fn()}] Adding dependencies')
    for package in pkgs:
        sha1 = try_or_error(lambda: f"{package['checksums'][0]['checksumValue']}", '')
        pkg_name = try_or_error(lambda: package["packageFileName"], package["name"])
        pkg_ver = try_or_error(lambda: package['versionInfo'], '')
        pkg_id = f'{pkg_name}-{pkg_ver}' if pkg_ver else pkg_name

        if sha1:
            pck = {
                "artifactId": f"{pkg_name}",
                "version": pkg_ver,
                "sha1": sha1,
                "systemPath": "",
                "optional": False,
                "filename": f"{pkg_name}",
                "checksums": {
                    "SHA1": sha1
                },
                "dependencyFile": ""
            }
        else:  # SHA1 not found
            pck = {}
            lang_types = []
            logger.debug(f'[{fn()}] Attempting to resolve library by language type')
            try:
                pck_ext = package["externalRefs"]  # execute SPDX structure file
                # like cpe:2.3:a:python:botocore:1.22.12:*:*:*:*:*:*:*
                for ext_ref in pck_ext:
                    if ext_ref["referenceCategory"] == "PACKAGE_MANAGER" or \
                            ext_ref['referenceCategory'] == "PACKAGE-MANAGER":
                        pkgname = re.search(r"pkg:(.*?)/", ext_ref['referenceLocator'],
                                            flags=re.DOTALL).group(1).strip()
                        pkg_data = SHA1CalcType.get_package_type(f_t=pkgname)
                        if pkg_data:
                            lang_types.append({pkg_data.libtype: pkg_data.ext})
                            break
            except:
                try:
                    if pkg_name != "NOASSERTION":
                        ext_name = os.path.splitext(pkg_name)[1][1:]
                        if ext_name == "":  # type of extension was not provided. Taken all possible types
                            for calctype_ in SHA1CalcType:
                                lang_types.append({calctype_.libtype: calctype_.ext})
                        else:
                            type_lst = SHA1CalcType.get_package_type_list_by_ext(ext=ext_name)
                            if type_lst == []:
                                for calctype_ in SHA1CalcType:  # Could not identify library extension
                                    # (could be part of the package name)
                                    lang_types.append({calctype_.libtype: calctype_.ext})
                            else:
                                for type_lst_ in type_lst:
                                    lang_types.append({type_lst_.libtype: type_lst_.ext})
                except:
                    pass

            sha1_ = ""
            res_err_msg = ""
            for l_type in lang_types:
                for key, value in l_type.items():
                    if pkg_ver:
                        logger.info(f'[{fn()}] Mend library search: {pkg_id}')
                        sha1_, lname_, err_, err_msg_ = search_lib_by_name(lib_name=pkg_name, lib_ver=pkg_ver, lib_type=key)
                        res_err_msg = err_msg_ if err_ == 3028 else res_err_msg  # Too many libraries were found
                    else:
                        sha1_ = ""
                        lname_ = ""
                        err_msg_ = ""
                if sha1_ != "":
                    pck = {
                        "artifactId": f"{lname_}",
                        "version": pkg_ver,
                        "sha1": sha1_,
                        "systemPath": "",
                        "optional": False,
                        "filename": f"{lname_}-{pkg_ver}.{value}",
                        "checksums": {
                            "SHA1": sha1_
                        },
                        "dependencyFile": ""
                    }
                    break
            if sha1_ == "" and pkg_name != "NOASSERTION":
                logger.info(f"Library not found: {pkg_id}. {res_err_msg if res_err_msg else err_msg_}")

        # if not check_el_inlist(pkg_name) and pck != {}:
        if pck != {}:
            if pkg_name not in added_el:
                added_el.append(f"{pkg_name}")  # we add element to list if was not added before
                dep.append(add_child(pck))
                logger.debug(f'[{fn()}] Dependency added: {pkg_id}, sha1: {sha1}')

    logger.debug(f'[{fn()}] Constructing update request')
    if args.scope_token == '' or args.scope_token is None:
        prj = [
            {
                "coordinates": {
                    "artifactId": f"{PrjID}"
                },
                "dependencies": dep
            }
        ]
    else:
        prj = [
            {
                "projectToken": f"{args.scope_token}",
                "dependencies": dep
            }
        ]

    out = {
        "updateType": f"{args.update_type}",
        "type": "UPDATE",
        "agent": "fs-agent",
        "agentVersion": "",
        "pluginVersion": "",
        "orgToken": f"{args.ws_token}",
        "userKey": f"{args.ws_user_key}",
        "product": f"{args.ws_product}",
        "productVersion": "",
        "timeStamp": ts,
        "projects": prj
    }
    return out


def get_files_from_pck(pck, sbom_f):
    file_lst = []
    try:
        f = pck['hasFiles']
        files = [*set(f)]
    except:
        files = []
    for file_ in files:
        file_lst.append(get_file_by_spdx(file_,sbom_f))
    return file_lst


def get_file_by_spdx(spdx, sbom_f):
    file_data = {}
    sbom_f_ = None
    for d in sbom_f:
        if d['SPDXID'] == spdx:
            sbom_f_ = d
            break

    if sbom_f_:
        sha1 = try_or_error(lambda: f"{sbom_f_['checksums'][0]['checksumValue']}","")
        vers = try_or_error(lambda: f"{sbom_f_['versionInfo']}","")
        try:
            file_data = {
                "artifactId": f"{spdx}",
                "version": vers,
                "sha1": sha1,
                "systemPath": "",
                "optional": False,
                "filename": f"{sbom_f_['fileName']}",
                "checksums": {
                    "SHA1": sha1
                },
                "dependencyFile": f"{sbom_f_['fileName']}"
            }
        except:
            pass
    return file_data


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
