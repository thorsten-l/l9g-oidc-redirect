FROM bellsoft/liberica-openjdk-alpine:21
WORKDIR /workspace
COPY l9g-oidc-redirect.jar /workspace/l9g-oidc-redirect.jar
ENTRYPOINT ["java", "-jar", "/workspace/l9g-oidc-redirect.jar"]
EXPOSE 40443
