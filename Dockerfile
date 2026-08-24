FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY static ./static
RUN pip install --no-cache-dir -e ".[postgres]"
ENV AUTH_HOST=0.0.0.0 AUTH_PORT=8090
EXPOSE 8090
CMD ["pisigma-auth"]
