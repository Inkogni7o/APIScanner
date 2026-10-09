"""Reproduce the bundled selection from pinned, already downloaded source archives.

Development helper only; never called by ADScan. Requires ruamel.yaml from the Semgrep extra.
Archives and commit IDs are stored in .project/vendor-cache; provenance ships with the package.
"""

import hashlib
import json
import tarfile
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".project" / "vendor-cache"
DESTINATION = ROOT / "src" / "adscan" / "rules" / "third_party"
SUPPLEMENTAL_LICENSES = {
    "gitlab": {
        "LICENSE-gosec": "https://raw.githubusercontent.com/securego/gosec/master/LICENSE.txt"
    },
    "njsscan": {"COPYING-GPL-3.0": "https://www.gnu.org/licenses/gpl-3.0.txt"},
}

GITLAB = """
go/crypto/rule-insecure-ignore-host-key.yml
go/crypto/rule-tlsversion.yml
go/filesystem/rule-decompression-bomb.yml
go/filesystem/rule-fileread.yml
go/filesystem/rule-ziparchive.yml
go/injection/rule-ssrf.yml
go/injection/rule-template-injection.yml
go/leak/rule-pprof-endpoint.yml
go/sql/rule-concat-sqli.yml
java/cookie/rule-HttpResponseSplitting.yml
java/cookie/rule-RequestParamToHeader.yml
java/crypto/rule-CipherDESInsecure.yml
java/crypto/rule-CipherECBMode.yml
java/crypto/rule-NullCipher.yml
java/crypto/rule-RsaNoPadding.yml
java/endpoint/rule-HostnameVerifier.yml
java/endpoint/rule-X509TrustManager.yml
java/inject/rule-CommandInjection.yml
java/inject/rule-FileDisclosureSpringFramework.yml
java/inject/rule-LDAPInjection.yml
java/inject/rule-OgnlInjection.yml
java/inject/rule-SpotbugsPathTraversalAbsolute.yml
java/password/rule-ConstantDBPassword.yml
java/password/rule-EmptyDBPassword.yml
java/script/rule-ScriptInjection.yml
java/script/rule-SpringSpelExpressionParser.yml
java/ssrf/rule-SSRF.yml
java/templateinjection/rule-TemplateInjection.yml
java/xml/rule-XmlDecoder.yml
java/xss/rule-XSSReqParamToServletWriter.yml
java/xxe/rule-XMLRdr.yml
javascript/dos/rule-non-literal-regexp.yml
javascript/pathtraversal/rule-non-literal-fs-filename.yml
javascript/react/rule-dangerouslysetinnerhtml.yml
javascript/xss/rule-mustache-escape.yml
python/deserialization/rule-dill.yml
python/deserialization/rule-marshal.yml
python/deserialization/rule-shelve.yml
python/deserialization/rule-yaml-load.yml
python/django/rule-django-extra-used.yml
python/escaping/rule-jinja2-autoescape-false.yml
python/files/rule-tarfile-unsafe-members.yml
python/flask/rule-app-debug.yml
python/log/rule-logging-config-insecure-listen.yml
python/sql/rule-hardcoded-sql-expression.yml
python/ssh/rule-ssh-nohost-key-verification.yml
python/ssl/rule-req-no-certvalid.yml
python/ssl/rule-unverified-context.yml
""".split()

NJSSCAN = [
    "njsscan/rules/semantic_grep/" + path
    for path in """
crypto/tls_node.yaml
database/nosql_injection.yaml
database/sql_injection.yaml
database/sql_injection_knex.yaml
eval/eval_deserialize.yaml
eval/eval_yaml_deserialize.yaml
eval/server_side_template_injection.yaml
exec/exec_shelljs.yaml
headers/header_cors_star.yaml
headers/header_injection.yaml
jwt/jwt_none_algorithm.yaml
redirect/open_redirect.yaml
ssrf/ssrf_node.yaml
traversal/archive_path_overwrite.yaml
traversal/path_traversal.yaml
xml/xxe_node.yaml
xss/xss_node.yaml
xss/xss_templates.yaml
""".split()
]


def vendor(name: str, repository: str, selection: list[str]) -> int:
    commit = (CACHE / f"{name}-commit.txt").read_text(encoding="utf-8").strip()
    archive_name = "gitlab-sast-rules" if name == "gitlab" else name
    yaml = YAML(typ="safe")
    files = []
    with tarfile.open(CACHE / f"{archive_name}.tar.gz") as archive:
        members = {member.name.split("/", 1)[-1]: member for member in archive.getmembers()}
        for source in ["LICENSE", *selection]:
            member = archive.extractfile(members[source])
            assert member is not None
            data = member.read()
            relative = source.removeprefix("njsscan/rules/semantic_grep/")
            target = DESTINATION / name / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            record = {"path": relative, "upstream_path": source, "sha256": hashlib.sha256(data).hexdigest()}
            if source != "LICENSE":
                document = yaml.load(data)
                record["rule_ids"] = [rule["id"] for rule in document["rules"]]
                record["license_notice"] = next(
                    (line for line in data.decode("utf-8").splitlines() if "License:" in line),
                    "LGPL-3.0 (repository LICENSE)",
                )
            files.append(record)
    for filename, source_url in SUPPLEMENTAL_LICENSES[name].items():
        data = (CACHE / filename).read_bytes()
        (DESTINATION / name / filename).write_bytes(data)
        files.append({
            "path": filename,
            "source_url": source_url,
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    manifest = {
        "repository": repository,
        "commit": commit,
        "modifications": "None; selected rule files are copied byte-for-byte.",
        "files": files,
    }
    (DESTINATION / name / "provenance.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return sum(len(record.get("rule_ids", [])) for record in files)


if __name__ == "__main__":
    gitlab = vendor("gitlab", "https://gitlab.com/gitlab-org/security-products/sast-rules", GITLAB)
    njsscan = vendor("njsscan", "https://github.com/ajinabraham/njsscan", NJSSCAN)
    print(f"Vendored {gitlab} GitLab and {njsscan} njsscan rules ({gitlab + njsscan} total).")
