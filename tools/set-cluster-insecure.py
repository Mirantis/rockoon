import sys
import yaml

kubeconfig = sys.argv[1]
print(f"Setting cluster 0 in {kubeconfig} to skip TLS cert verification...")

with open(kubeconfig, "r") as f:
    config = yaml.safe_load(f)
config["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
config["clusters"][0]["cluster"].pop("certificate-authority-data", None)
with open(kubeconfig, "w") as f:
    yaml.dump(config, f)
