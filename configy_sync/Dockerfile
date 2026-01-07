FROM python:3.14.2-alpine3.22

WORKDIR /usr/src/app

RUN pip install pipenv
# Default version of sed in alpine isn't the full GNU one, so install that
RUN apk add sed openssh-client

COPY ssh-config /root/.ssh/config

RUN echo "53 * * * * cd `pwd` && /usr/local/bin/pipenv --quiet run python -u sync.py >> /var/log/cron.log 2>&1" | crontab -
COPY startup.sh .

COPY Pipfile* ./
RUN pipenv install
COPY *.py ./

CMD [ "./startup.sh"]