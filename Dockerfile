FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
  curl \
  apt-transport-https \
  gnupg \
  lsb-release

RUN curl https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -

RUN echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list

RUN apt-get update && apt-get install -y trivy

RUN apt-get update && apt-get install -y \
  curl

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY build/linux/vulny /vulny

