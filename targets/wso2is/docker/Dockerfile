# Used by build.sh; the build context holds an extracted, patched pack in ./wso2is.
FROM eclipse-temurin:21-jdk
RUN useradd --system --create-home wso2
COPY --chown=wso2 wso2is /home/wso2/wso2is
USER wso2
EXPOSE 9443
ENTRYPOINT ["/home/wso2/wso2is/bin/wso2server.sh"]
