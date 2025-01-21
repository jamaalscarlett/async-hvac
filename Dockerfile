FROM python:3.12-slim-bullseye

COPY download_vault.sh /download_vault.sh
COPY docker_tests.sh /docker_tests.sh
COPY async_hvac/ /src/async_hvac/
COPY test-fixtures/ /src/test-fixtures/
COPY tox.ini /src/
COPY requirements-dev.txt /src/

RUN apt update
RUN apt install -y wget zip gcc
RUN pip install uv
RUN uv tool install tox --with tox-uv
ENV PATH=/root/.local/bin:$PATH
WORKDIR /src

CMD ["/docker_tests.sh"]