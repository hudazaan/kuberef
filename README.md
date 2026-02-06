# Kuberef

**Kuberef** is a lightweight, cloud-native CLI tool designed to validate Kubernetes Secret references before you deploy. 

It bridges the gap between static YAML manifests and your live cluster state, ensuring that your Pods won't fail at runtime due to missing `secretKeyRef` dependencies.

---

## Features

- **Automated Dependency Discovery**: Scans Kubernetes `Deployment` and `Pod` manifests for `valueFrom.secretKeyRef` entries.
- **Live Cluster Auditing**: Cross-references discovered secrets against the live Kubernetes API in real-time.
- **Rich Terminal UI**: Utilizes the `Rich` library to provide clear, color-coded PASS/FAIL status tables.
- **Namespace Aware**: Supports targeted auditing across different namespaces using the `-n` or `--namespace` flags.
- **Python-Powered**: Built with `Typer`, `PyYAML`, and the official `kubernetes` Python client.

---

## Installation

### From TestPyPI (Current Release)

⚠️ Note: Since this is a TestPyPI release, please use the installation command below to ensure all dependencies (PyYAML, Typer, etc.) are pulled correctly from the main PyPI registry:


```bash
pip install --no-cache-dir --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ kuberef
```

### From Source (Development)

If you want to run the tool from source or contribute:

```bash
git clone https://github.com/hudazaan/kuberef.git
cd kuberef
poetry install
poetry run kuberef path/to/your/k8s-manifest.yaml
```

---

## Usage

Basic check against the `default` namespace:
```bash
kuberef deployment.yaml
```

Check a specific namespace:
```bash
kuberef deployment.yaml --namespace production
```

Or run the auditor by providing the path to your Kubernetes manifest:

```bash
kuberef <YOUR_FILE>.yaml --namespace <YOUR_NAMESPACE>
```

Example: if your file is `myapp.yaml` and your namespace is `staging`: 
```bash
kuberef myapp.yaml --namespace staging
```

---

## Technical Architecture

- **Parser**: Leverages `PyYAML` to traverse the Pod specification tree.
- **Client**: Uses `load_kube_config()` to authenticate with your local `~/.kube/config`.
- **CLI**: Built on `Typer` for high-performance, self-documenting command-line interfaces.
- **Validation**: Compares the set of required secrets against the list of available secrets via `v1.list_namespaced_secret`.

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b YOUR-BRANCH-NAME`)
3. Run tests (`poetry run pytest`)
4. Commit your Changes (`git commit -m 'your message'`)
5. Push to the Branch (`git push origin YOUR-BRANCH-NAME`)
6. Open a Pull Request

---

## Author 

Built with ❤️ by **Huda Naaz**

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
