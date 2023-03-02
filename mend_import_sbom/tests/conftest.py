from pytest import fixture
from argparse import Namespace


def pytest_addoption(parser):
    parser.addoption("--projectName", action="store", default="Test Project")
    parser.addoption("--projectToken", action="store", default ='Token')
    parser.addoption("--apiKey", action="store", default ='apiKey')
    parser.addoption("--userKey", action="store", default ='UserKey')
    parser.addoption("--sbom", action="store", default ='./mend_import_sbom/tests/test.json')
    parser.addoption("--updateType", action="store", default ='OVERRIDE')
    parser.addoption("--productToken", action="store", default ='Test Product Token')
    parser.addoption("--mendUrl", action="store", default ='saas.whitesourcesoftware.com')
    parser.addoption("--offline", action="store", default =False)
    parser.addoption("--out", action="store", default ='./')


def pytest_configure(config):
    global args
    args = Namespace(ws_project=config.getoption("projectName"), ws_user_key=config.getoption("userKey"),ws_token=config.getoption("apiKey"),
                     scope_token=config.getoption("projectToken"),sbom=config.getoption("sbom"), update_type=config.getoption("updateType"),
                     ws_product=config.getoption("productToken"),ws_url=config.getoption("mendUrl"),load=config.getoption("offline"),out_dir=config.getoption("out"))
    return args


@fixture()
def project(request):
    return request.config.getoption("--projectName")