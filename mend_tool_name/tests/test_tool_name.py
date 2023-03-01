import pytest
import conftest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__),
                  os.pardir)
)

sys.path.append(PROJECT_ROOT)
from mend_import_sbom import import_sbom


def test_create_body(project):
    out = import_sbom.create_body(conftest.args)
    assert out['orgToken'] != "" and out['userKey'] != "" and out['userKey'] != "product"


if __name__ == '__main__':
    pytest.main()
