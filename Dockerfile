FROM tasox/demailer:linux-amd64-latest

COPY deMailer.zip /home/

WORKDIR /home

RUN unzip deMailer.zip

RUN rm deMailer.zip

WORKDIR /home/deMailer

RUN pip install -r requirements.txt