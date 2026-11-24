# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build the extension jar.
# ---------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
# Warm the dependency cache (best effort; ignored if offline resolution fails).
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B clean package

# ---------------------------------------------------------------------------
# Stage 2: the Guacamole web application with the extension installed.
#
# The entrypoint treats the GUACAMOLE_HOME env var as a *template*: it copies
# its contents into the real runtime home. We use it to install our Vault SSH
# OTP extension and its guacamole.properties. The MySQL auth backend is wired
# up separately by the entrypoint from the MYSQL_* environment variables.
# ---------------------------------------------------------------------------
FROM guacamole/guacamole:1.5.5

ENV GUACAMOLE_HOME=/opt/guacamole-home

COPY deploy/guacamole/guacamole.properties /opt/guacamole-home/guacamole.properties
COPY --from=build /build/target/guacamole-auth-vault-ssh-otp-1.1.0.jar \
                  /opt/guacamole-home/extensions/guacamole-auth-vault-ssh-otp.jar
