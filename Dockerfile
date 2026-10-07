# syntax=docker/dockerfile:1

# ---- Runtime image: standard library only, no third-party packages --------
FROM python:3.11-slim AS runtime
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0
# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
COPY --chown=appuser:appuser app ./app
USER appuser
EXPOSE 8080
CMD ["python", "-m", "app.server"]

# ---- Verification image: adds pytest on top of the runtime image -----------
FROM runtime AS test
USER root
COPY requirements-dev.txt ./requirements-dev.txt
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY scripts ./scripts
COPY tests ./tests
RUN chown -R appuser:appuser /srv
USER appuser
# "Build" the application: byte-compile all sources so syntax/import errors
# fail the image build rather than the first request.
RUN python -m compileall -q app tests scripts
