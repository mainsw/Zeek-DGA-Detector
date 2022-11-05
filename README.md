# Zeek DGA Detector
DGA Domain Detector utilizing Zeek DNS logs
<br/><br/>

# Overview
Zeek에서 생성하는 DNS 로그 데이터를 활용하여, DGA 도메인 실시간 탐지 및 경고를 수행하는 도구입니다.

딥러닝 기반으로 DGA 도메인을 예측하고, 탐지시 텍스트 파일 및 Elasticsearch에 기록하며, Slack 경고를 생성합니다.
<br/><br/>

# Function
- 딥러닝 기반 DGA 도메인 탐지
- txt 탐지 기록
- Elasticsearch 탐지 기록
- Slack 탐지 알림
<br/><br/>

# Requirements
Python 3.7+ 이상이 필요합니다.

Python 3.7.4 에서 테스트되었습니다.

다음과 같은 추가적인 외부 모듈이 필요합니다.
```sh
- zat
- dgaintel
- elasticsearch
- slack-sdk
```

또한, Zeek 로그 파일이 저장되고 있는 환경 내부에서 실행해야 합니다.
<br/><br/>

# Installation
git clone한 후 pip를 사용하여 필요한 모듈을 설치합니다.
```sh
$ git clone https://github.com/mainsw/zeek-dga-detector
$ cd zeek-dga-detector
$ pip install -r requirements.txt

# Elasticsearch 7 버전인 경우
$ pip install elasticsearch==7.0.0

# Elasticsearch 8 버전인 경우
$ pip install elasticsearch==8.0.0
```

<br/>zeek-dga.py를 환경에 맞게 수정합니다.
```sh
# Elasticsearch 연결 설정 (본인 환경에 맞게 수정)
es = Elasticsearch('http://127.0.0.1:9200')

# Elasticsearch Index Name 설정 (수정 가능, 중복되지 않도록 설정)
index_name = 'dga'

# Slack Webhook 설정 (본인 환경에 맞게 수정)
webhookUrl = "https://your.webhook.url"

# Zeek dns.log 경로 설정 (본인 환경에 맞게 수정)
reader = zeek_log_reader.ZeekLogReader('/opt/zeek/logs/current/dns.log', tail=True)

# DGA 도메인 탐지 txt 로그 경로 설정 (본인 환경에 맞게 수정)
dgaTxtPath = "/home/admin/dga.txt"
```

<br/>zeek-dga.py를 실행합니다.
```sh
$ python zeek-dga.py
```
