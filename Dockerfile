FROM python:alpine
RUN virtualenv virtualenv && \
    source venv/bin/activate
RUN mkdir -p /app/script
RUN touch /app/requirements.txt
RUN pip install -r /app/requirements.txt
RUN echo '#!/bin/sh' > /app/script/entrypoint.sh && \
    echo '' >> /app/script/entrypoint.sh && \
    chmod +x /app/script/entrypoint.sh
WORKDIR /app