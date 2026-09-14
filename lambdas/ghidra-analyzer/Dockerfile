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

# Real Lambda only allows writes to /tmp -- everywhere else is read-only.
# Ghidra/pyghidra resolve their config/cache directories from Java's
# user.home, which on Linux the JVM reads from the OS passwd database
# (getpwuid), NOT the HOME env var -- so HOME=/tmp alone does not
# redirect it (verified: it still tried to write to /root/.config/ghidra
# under a simulated read-only root). JDK_JAVA_OPTIONS is auto-read by any
# `java`-launched subprocess (Ghidra's LaunchSupport preflight check uses
# one), which covers that half; the embedded JVM that PyGhidra boots
# in-process via JPype does not go through the `java` launcher at all, so
# it needs -Duser.home injected directly into its own startup args (done
# in analysis/extract.py via HeadlessPyGhidraLauncher.vm_args).
ENV HOME=/tmp
ENV TMPDIR=/tmp
ENV JDK_JAVA_OPTIONS=-Duser.home=/tmp

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

# PyGhidra (native CPython bridge to Ghidra, replacing the old Jython
# scripting engine) ships its own wheels -- including JPype, its Java
# bridge -- inside the Ghidra distribution for offline install. Installing
# at build time (rather than via its own interactive first-run installer)
# keeps this consistent with "resolve dependencies at build time, no
# network access needed at runtime."
RUN pip install --no-index \
    --find-links=/opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist \
    pyghidra

# handler.py drives PyGhidra natively (import pyghidra; pyghidra.start()) in
# the same process -- no analyzeHeadless subprocess, no Ghidra Project
# files on disk, no -postScript log-scraping.
COPY handler.py ${LAMBDA_TASK_ROOT}/
COPY analysis/ ${LAMBDA_TASK_ROOT}/analysis/
CMD ["handler.lambda_handler"]
