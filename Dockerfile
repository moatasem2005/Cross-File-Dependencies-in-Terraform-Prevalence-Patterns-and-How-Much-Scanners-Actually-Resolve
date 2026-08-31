# Pinned environment for the RQ4 cross-file resolution experiment.
#
# These are the exact versions that produced the results reported in the manuscript,
# as recorded in results/rq4_manifest.json. Pinning them here makes the reported
# verdicts reproducible; override the build args only to test other releases.
#
# Build:  docker build -t crossfile-rq4 .
# Run:    docker run --rm -v "$PWD/rq4_out:/out" crossfile-rq4
FROM python:3.11-slim

ARG CHECKOV_VERSION=3.3.13
ARG TFSEC_VERSION=v1.28.14
ARG TERRASCAN_VERSION=1.19.9
ARG TRIVY_VERSION=0.74.0
ARG TERRAFORM_VERSION=1.10.5

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" && checkov --version

RUN curl -fsSL "https://github.com/aquasecurity/tfsec/releases/download/${TFSEC_VERSION}/tfsec-linux-amd64" \
      -o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec && tfsec --version

RUN curl -fsSL "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz" \
      -o /tmp/ts.tgz && tar -xzf /tmp/ts.tgz -C /tmp terrascan \
      && mv /tmp/terrascan /usr/local/bin/ && chmod +x /usr/local/bin/terrascan \
      && rm /tmp/ts.tgz && terrascan version

RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      -o /tmp/tv.tgz && tar -xzf /tmp/tv.tgz -C /tmp trivy \
      && mv /tmp/trivy /usr/local/bin/ && chmod +x /usr/local/bin/trivy \
      && rm /tmp/tv.tgz && trivy --version

# Terraform is used for syntax validation only (`fmt -check`, and optionally
# `init -backend=false` + `validate` in the separate validation pass).
RUN curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
      -o /tmp/tf.zip && unzip -q /tmp/tf.zip -d /usr/local/bin && rm /tmp/tf.zip && terraform version

WORKDIR /work
COPY src/ /work/src/
ENV RQ4_OUT=/out
CMD ["python", "/work/src/rq4_experiment.py"]
