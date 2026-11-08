"""WSL bridge. Secrets arrive on stdin and reach Android tools via process env only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def linux_path(value):
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return "/mnt/" + value[0].lower() + "/" + value[3:].replace("\\", "/")
    return value


def run(args, **options):
    return subprocess.run(args, check=True, **options)


data = json.load(sys.stdin)
os.environ["SRKN_ANDROID_STORE_PASS"] = data["password"]
os.environ["JAVA_HOME"] = "/usr/lib/jvm/java-17-openjdk-amd64"
store = linux_path(data["keystore"])
alias = "sorryrkn-production"
if data["action"] == "create":
    assert not Path(store).exists(), "Refusing to overwrite an Android signing key"
    run([os.environ["JAVA_HOME"] + "/bin/keytool", "-genkeypair", "-keystore", store,
         "-storetype", "PKCS12", "-alias", alias, "-storepass:env", "SRKN_ANDROID_STORE_PASS",
         "-keypass:env", "SRKN_ANDROID_STORE_PASS", "-keyalg", "RSA", "-keysize", "4096",
         "-validity", "10000", "-dname", "CN=SorryRKN Android, O=Def01d"],
        stdout=subprocess.DEVNULL)
elif data["action"] == "sign":
    sdk = linux_path(data["build_tools"])
    source, output = map(linux_path, (data["input"], data["output"]))
    assert not Path(output).exists(), "Refusing to overwrite an existing signed APK"
    badging = run([sdk + "/aapt", "dump", "badging", source], capture_output=True, text=True).stdout
    package = re.search(r"^package: name='([^']+)'", badging)
    assert package and package.group(1) == data["application_id"], "Unexpected Android package"
    with tempfile.TemporaryDirectory(prefix="sorryrkn-sign-") as temp:
        aligned = str(Path(temp) / "aligned.apk")
        run([sdk + "/zipalign", "-P", "16", "-f", "4", source, aligned])
        run([sdk + "/apksigner", "sign", "--ks", store, "--ks-key-alias", alias,
             "--ks-pass", "env:SRKN_ANDROID_STORE_PASS", "--key-pass", "env:SRKN_ANDROID_STORE_PASS",
             "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
             "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--out", output, aligned])
        run([sdk + "/apksigner", "verify", "--verbose", output], stdout=subprocess.DEVNULL)
        run([sdk + "/zipalign", "-c", "-P", "16", "4", output])
else:
    raise ValueError("Unknown signing operation")

cert = run([os.environ["JAVA_HOME"] + "/bin/keytool", "-exportcert", "-keystore", store,
            "-alias", alias, "-storepass:env", "SRKN_ANDROID_STORE_PASS"], capture_output=True).stdout
print(json.dumps({"certificate_sha256": hashlib.sha256(cert).hexdigest()}))
