from enum import Enum
import os


class aliases(Enum):  # List of aliases for params
    apikey = ("--apiKey","--api-key","--orgToken")
    userkey = ("--user-key","--userKey")
    projectkey = ("--scope","--projectToken")
    productkey = ("--productToken","--product")
    url = ("--url","--mendUrl")
    output = ("--out","--dir")
    sbom = ("--sbom","--input")
    version = ("--version","-v")

    @classmethod
    def get_aliases_str(cls, key):
        res = list()
        for elem_ in cls.__dict__[key].value:
            res.append(elem_)
            if elem_ != elem_.lower():
                res.append(elem_.lower())
        return res


class varenvs(Enum):  # Lit of Env.variables
    wsuserkey = ("WS_USERKEY", "MEND_USERKEY")
    wsapikey = ("MEND_APIKEY","WS_APIKEY","WS_TOKEN")
    wsurl = ("WS_WSS_URL","MEND_WSS_URL","WS_URL","MEND_URL")
    wsscope = ("WS_SCOPE","MEND_SCOPE")
    wsproduct = ("WS_PRODUCTTOKEN", "MEND_PRODUCTTOKEN")

    @classmethod
    def get_env(cls, key):
        res = ""
        for el_ in cls.__dict__[key].value:
            res = os.environ.get(el_)
            if res:
                break
        return res


class Templates(Enum):  # Specific patterns of lib name and version
    # First element is pattern of delimiter in library name.
    # Second item contains possible specific symbols in version info that should be removed
    github = (":", "^")


class SHA1CalcType(Enum):  # list with supported packages
    maven = ("y", "JAVA", "jar", "maven",1)  # jar
    pypi = ("n", "PYTHON", "whl", "pypi",2)  # whl
    npm = ("y", "NPM", "js", "npm",3)  # js
    cdnjs = ("y", "CDNJS", "js", "cdnjs",4)  # js
    dotnet = ("y", "NUGET", "exe", ".net",5)  # exe
    bower = ("y", "BOWER", "jar", "bower",6)  # jar
    ocaml = ("n", "Opam", "ml", "ocaml",7)  # ml
    go = ("n", "GO", "go", "go",8)  # go
    nuget = ("y", "NUGET", "ng", "nuget",9)  # ng
    rpm = ("n", "RPM", "rpm", "rpm",10)  # rpm
    composer = ("n", "PHP", "php", "php",11)  # php
    cocoapods = ("n", "CocoaPods", "pod", "cocoapods",12)
    cran = ("n", "R", "r", "cran",13)  # r
    gem = ("y", "RUBY", "gem", "ruby",14)  # gem
    rust = ("y", "RUST", "rs", "rust",15)  # rs
    rlib = ("y", "RUST", "rlib", "rust",16)  # rlib
    hex = ("y", "HEX", "hex", "hex",17)  # hex, h86
    alpine = ("n", "Alpine", "apk", "alpine",18)

    @property
    def lower_case(self):
        return self.value[0]

    @property
    def language(self):
        return self.value[1]

    @property
    def ext(self):
        return self.value[2]

    @property
    def libtype(self):
        return self.value[3]

    @property
    def order(self):
        return self.value[4]

    @classmethod
    def get_el_by_name(cls, name: str):
        res = None
        for el_ in cls:
            if el_.name == name:
                res = el_
                break
        return res

    @classmethod
    def get_package_data(cls, lng: str):
        res = ""
        for el_ in cls:
            if el_.language == lng:
                res = el_.lower_case
                break
        return res

    @classmethod
    def get_package_type(cls, f_t: str):
        try:
            return cls.__dict__[f_t]
        except:
            return []

    @classmethod
    def get_package_type_list_by_ext(cls, ext: str):
        res = []
        for el_ in cls:
            if el_.ext == ext:
                res.append(el_)
        return res
