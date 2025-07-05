FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
RUN useradd --create-home --uid 1000 appuser && chown -R appuser /app
USER appuser
ENTRYPOINT ["qs_kdf"]
CMD ["--help"]
