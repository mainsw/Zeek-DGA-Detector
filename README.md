# Zeek DGA Detector
DGA Domain Detector utilizing Zeek DNS logs and Deep Learning

![이미지 로드에 실패했습니다. 리포지토리에서 직접 확인해 주세요.](https://github.com/mainsw/Zeek-DGA-Detector/blob/main/img/detection-demo.gif?raw=true)

<br/><br/>

## Overview
Zeek에서 생성하는 DNS 로그 데이터를 활용하여, DGA 도메인 실시간 탐지 및 경고를 수행하는 도구입니다.

딥러닝 기반으로 DGA 도메인을 예측하고, 탐지시 텍스트 파일 및 Elasticsearch에 기록하며, Slack 경고를 생성합니다.
<br/><br/>
![이미지 로드에 실패했습니다. 리포지토리에서 직접 확인해 주세요.](https://github.com/mainsw/Zeek-DGA-Detector/blob/main/img/zeek-dga-structure.png?raw=true)
<br/><br/>

## Features
- 딥러닝 기반 DGA 도메인 탐지
- txt 탐지 기록
- Elasticsearch 탐지 기록
- Slack 탐지 알림
<br/><br/>

## Requirements
다음과 같은 구성요소가 사전에 구축되어 있어야 합니다.

```sh
- Linux OS
- Zeek
- Elasticsearch
- Slack Webhook
- Python 3.7 이상
```

<br/>Python 3.7.4 에서 테스트되었습니다.

다음과 같은 파이썬 외부 모듈을 사용합니다.
```sh
# 내부 코드 작동에 필요
- zat
- dgaintel
- elasticsearch
- slack-sdk

# 설치에 필요
- setuptools
```

<br/>또한, Zeek 로그 파일이 저장되고 있는 환경 내부에서 실행해야 합니다.
<br/><br/>

## Installation
루트 권한으로 진행합니다.

다음과 같이 설치를 진행합니다.

```sh
# Elasticsearch 7 버전인 경우
pip3 install git+https://github.com/mainsw/zeek-dga-detector.git elasticsearch==7.0.0

# Elasticsearch 8 버전인 경우
pip3 install git+https://github.com/mainsw/zeek-dga-detector.git elasticsearch==8.0.0
```

<br/>설치하면서 zeekdga.py가 PATH에 복사됩니다.

간단히 다음 명령으로 Zeek-DGA-Detector를 실행하여, 작동에 필요한 인자와 설명을 확인할 수 있습니다.
```sh
zeekdga.py --help
```

```sh
프로그램 작동을 위한 인자를 다음과 같이 설정해 주세요.

optional arguments:
  -h, --help         show this help message and exit
  --es ES            Elasticsearch 연결 설정 (default: http://127.0.0.1:9200)
  --index INDEX      Elasticsearch Index Name 설정 (default: dga)
  --zeekdns ZEEKDNS  Zeek current/dns.log 경로 설정 (default: /opt/zeek/logs/current/dns.log)
  --txtlog TXTLOG    [required] DGA 도메인 탐지 txt 로그 경로 설정 (ex: /home/admin/dgalog.txt)
  --webhook WEBHOOK  [required] Slack Webhook URL 설정 (ex: https://hooks.slack.com/services/XXX)
```
<br/>--es, --index, --zeekdns는 설정하지 않으면 기본값으로 적용됩니다.

--txtlog, --webhook은 반드시 직접 설정해야 합니다.

다음과 같이 적절한 인자와 함께 실행하면 끝입니다. 모든 기능이 작동합니다.

```sh
zeekdga.py --txtlog /home/admin/dgalog.txt --webhook https://hooks.slack.com/services/XXX
```

```sh
=== Configuration ===
http://127.0.0.1:9200
dga
https://hooks.slack.com/services/XXX
/opt/zeek/logs/current/dns.log
/home/admin/dgalog.txt
=== Configuration ===
Successfully monitoring /opt/zeek/logs/current/dns.log...

=======================
storage.googleapis.com
0.0002733171
CrUbqN2fpJEOjRP0Gk
=======================
```