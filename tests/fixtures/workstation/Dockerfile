FROM scratch
COPY fixture /fixture
COPY --chown=65532:65532 state /state
USER 65532:65532
ENTRYPOINT ["/fixture"]
