# Stage 1: Ghidra headless static analysis, packaged as a Lambda container image.
FROM public.ecr.aws/lambda/python:3.13

# Ghidra's headless analyzer is a JVM application; the Lambda Python base
# image ships no JDK. Ghidra 12.x requires JDK 21 -- Amazon Corretto 21 is
# one of the JDK distributions Ghidra's own docs list as supported, and
# it's already packaged for this base image's package manager (dnf).
# NOTE: needs "-devel" (the actual JDK: javac, jmods), not "-headless"
# (JRE only) -- Ghidra's launcher checks for a real JDK and refuses to
# start against a JRE-only install, even though `java` itself runs fine.
RUN dnf install -y java-21-amazon-corretto-devel unzip tar gzip \
    && dnf clean all

# Ghidra's launch script looks for JAVA_HOME and, if unset, tries to prompt
# interactively to confirm a detected JDK -- there's no TTY in a Lambda
# container, so that prompt just hangs/fails. Set it explicitly.
ENV JAVA_HOME=/usr/lib/jvm/java-21-amazon-corretto.x86_64

# Pin an exact Ghidra release and verify it against the checksum NSA
# publishes in the GitHub release notes before unpacking anything. This
# pipeline exists to analyze untrusted binaries -- the one thing worse
# than that would be doing it with a tampered copy of the analyzer itself.
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_20260817.zip
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

RUN curl -fsSL -o /tmp/ghidra.zip "${GHIDRA_URL}" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# --- Lambda handler (next iteration) ---
# COPY requirements.txt ${LAMBDA_TASK_ROOT}/
# RUN pip install -r ${LAMBDA_TASK_ROOT}/requirements.txt
# COPY handler.py ${LAMBDA_TASK_ROOT}/
# COPY ghidra_scripts/ ${LAMBDA_TASK_ROOT}/ghidra_scripts/
# CMD ["handler.lambda_handler"]
