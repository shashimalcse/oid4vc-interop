FROM gradle:8.14-jdk21 AS build
WORKDIR /src
COPY settings.gradle.kts build.gradle.kts ./
COPY src ./src
RUN gradle --no-daemon -q installDist

FROM eclipse-temurin:21-jre
COPY --from=build /src/build/install/vcit-eudi-wallet /opt/wallet
EXPOSE 7007
ENTRYPOINT ["/opt/wallet/bin/vcit-eudi-wallet"]
