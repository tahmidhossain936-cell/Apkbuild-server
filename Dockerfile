# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    JAVA_HOME=/usr/lib/jvm/java-17 \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    GRADLE_HOME=/opt/gradle/gradle-8.14.5 \
    GRADLE_USER_HOME=/opt/gradle-cache \
    ANDROID_BUILD_TOOLS_VERSION=36.0.0 \
    ANDROID_COMPILE_SDK=36 \
    GRADLE_OPTS="-Dorg.gradle.daemon=false -Dorg.gradle.workers.max=2 -Xmx1024m -XX:MaxMetaspaceSize=512m" \
    TMP_BASE_DIR=/tmp/apk-builder

# 1. Install Java 17 JDK, system build utilities, and tini for graceful signal handling
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless \
        ca-certificates \
        curl \
        unzip \
        zip \
        bash \
        procps \
        tini \
        zlib1g \
        libstdc++6 \
    && ln -s /usr/lib/jvm/java-17-openjdk-* "${JAVA_HOME}" \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Gradle 8.14.5 with SHA-256 verification
ARG GRADLE_VERSION=8.14.5
ARG GRADLE_SHA256=6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854
RUN mkdir -p /opt/gradle "${GRADLE_USER_HOME}" \
    && curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip \
    && echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum -c - \
    && unzip -q /tmp/gradle.zip -d /opt/gradle \
    && rm -f /tmp/gradle.zip \
    && ln -s "${GRADLE_HOME}/bin/gradle" /usr/local/bin/gradle

# 3. Install Android SDK Command-Line Tools, Platform Tools, API 36 Platform, and Build Tools 36.0.0
ARG CMDLINE_TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip
RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" \
    && curl -fsSL "${CMDLINE_TOOLS_URL}" -o /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-extract \
    && mv /tmp/cmdline-extract/cmdline-tools "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm -rf /tmp/cmdline-tools.zip /tmp/cmdline-extract

ENV PATH="${JAVA_HOME}/bin:${GRADLE_HOME}/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/build-tools/${ANDROID_BUILD_TOOLS_VERSION}:${PATH}"

RUN yes | sdkmanager --licenses > /dev/null \
    && sdkmanager --install \
        "platform-tools" \
        "platforms;android-${ANDROID_COMPILE_SDK}" \
        "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" \
    && chmod -R a+rX "${ANDROID_HOME}"

# 4. Application setup
WORKDIR /app

COPY package*.json ./
RUN if [ -f package-lock.json ]; then \
        npm ci --omit=dev; \
    else \
        npm install --omit=dev; \
    fi

COPY . .

# Prepare ephemeral workspace directory
RUN mkdir -p "${TMP_BASE_DIR}/builds" "${TMP_BASE_DIR}/keystores" \
    && chmod 700 "${TMP_BASE_DIR}"

# Render sets PORT dynamically (default 10000)
EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "const p=process.env.PORT||10000;fetch('http://127.0.0.1:'+p+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server.js"]
