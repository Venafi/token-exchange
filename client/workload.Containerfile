FROM ubuntu:latest

ARG AWSTARGETARCH

RUN \
    apt-get update -y && \
    apt-get install -y curl jq unzip gpg vim && \
    \
    apt-get install -y mandoc && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-$AWSTARGETARCH.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws && \
    \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y google-cloud-cli && \
    \
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash && \
    \
    apt-get purge -y unzip gpg && \
    rm -rf /var/lib/apt/lists/*

COPY workload.init.sh /usr/local/bin/workload.init.sh
COPY fetch-aws.sh /fetch-aws.sh
COPY fetch-gcp.sh /fetch-gcp.sh
COPY fetch-azure.sh /fetch-azure.sh

RUN chmod +x /usr/local/bin/workload.init.sh && \
    chmod +x /fetch-aws.sh && \
    chmod +x /fetch-gcp.sh && \
    chmod +x /fetch-azure.sh

WORKDIR /

# vim: syntax=Dockerfile
