FROM python:3.14-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*
COPY docker/init_secret.py /tests/init_secret.py
COPY docker/trustpoint/runtime_config.py /etc/trustpoint/runtime_config.py
COPY docker/trustpoint/lock_application.sh /etc/trustpoint/lock_application.sh
COPY docker/trustpoint/entrypoint.sh /etc/trustpoint/entrypoint.sh
COPY docker/trustpoint/wizard/ /etc/trustpoint/wizard/
COPY docker/trustpoint/wizard/sudoers /etc/sudoers
COPY tests/docker_security/runtime_boundary_smoke.py /tests/runtime_boundary_smoke.py
RUN chown -R root:root /etc/trustpoint && chmod -R 755 /etc/trustpoint && chmod 440 /etc/sudoers && visudo -c
CMD ["python3", "-I", "/tests/runtime_boundary_smoke.py"]
