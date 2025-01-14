FROM python:3.12-slim-bullseye

COPY run_tests.sh /run_tests.sh
COPY async_hvac/ /src/async_hvac/
COPY test/ /src/test/
COPY tox.ini /src/
COPY requirements-dev.txt /src/

RUN apt update
RUN apt install -y wget zip gcc
RUN pip install uv tox
RUN uv tool install tox --with tox-uv
ENV PATH=/root/.local/bin:$PATH
WORKDIR /src

CMD ["/run_tests.sh"]