# Zeek DGA Detector
DGA Domain Detector utilizing Zeek DNS logs and Deep Learning

Zeek DNS 로그와 딥러닝을 활용하는 DGA 도메인 탐지기
<br/><br/>

## Demo
![이미지 로드에 실패했습니다. 리포지토리에서 직접 확인해 주세요.](https://github.com/mainsw/Zeek-DGA-Detector/blob/main/img/detection-demo.gif?raw=true)
DGA Domain Source: [Netlab 360 DGA Domain List](https://data.netlab.360.com/feeds/dga/dga.txt)
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

<br/>Python 3.7.4, Zeek 4 에서 테스트되었습니다.

다음과 같은 파이썬 외부 모듈을 사용합니다.
```sh
# 내부 코드 작동에 필요
- zat
- dgaintel
- elasticsearch
- slack-sdk
- pytz
- python-whois

# 설치에 필요
- setuptools
```

<br/>또한, Zeek 로그 파일이 저장되고 있는 환경 내부에서 실행해야 합니다.
<br/><br/>

## Installation
루트 계정으로 진행합니다.

다음과 같이 설치를 진행합니다.

```sh
# Elasticsearch 7 버전인 경우
pip3 install git+https://github.com/mainsw/zeek-dga-detector.git elasticsearch==7.0.0

# Elasticsearch 8 버전인 경우
pip3 install git+https://github.com/mainsw/zeek-dga-detector.git elasticsearch==8.0.0
```

<br/>설치하면서 zeekdga.py가 PATH에 복사됩니다.

간단히 다음 명령으로 Zeek DGA Detector를 실행하여, 작동에 필요한 인자와 설명을 확인할 수 있습니다.
```sh
zeekdga.py --help
```

```sh
'=== Timezones ==='
[   'Africa/Abidjan',
    'Africa/Accra',
    'Africa/Addis_Ababa',
	....]
  
usage: zeekdga.py [-h] [--es ES] [--index INDEX] [--zeekdns ZEEKDNS] --txtlog
                  TXTLOG --webhook WEBHOOK [--timezone TIMEZONE]
                  
프로그램 작동을 위한 인자를 다음과 같이 설정해 주세요.

optional arguments:
  -h, --help          show this help message and exit
  --es ES             Elasticsearch 연결 설정 (default: http://127.0.0.1:9200)
  --index INDEX       Elasticsearch Index Name 설정 (default: dga)
  --zeekdns ZEEKDNS   Zeek current/dns.log 경로 설정 (default: /opt/zeek/logs/current/dns.log)
  --txtlog TXTLOG     [required] DGA 도메인 탐지 txt 로그 경로 설정 (ex: /home/admin/dgalog.txt)
  --webhook WEBHOOK   [required] Slack Webhook URL 설정 (ex: https://hooks.slack.com/services/XXX)
  --timezone TIMEZONE [required] 현재 Timezone 설정, 상단에 출력된 리스트 참조 (ex: Asia/Seoul)
  
```
<br/>--es, --index, --zeekdns는 설정하지 않으면 기본값으로 적용됩니다.

--txtlog, --webhook, --timezone은 반드시 직접 설정해야 합니다.

다음과 같이 적절한 인자와 함께 실행하면 끝입니다. 모든 기능이 작동합니다.

```sh
zeekdga.py --txtlog /home/admin/dgalog.txt --webhook https://hooks.slack.com/services/XXX --timezone Asia/Seoul
```

```sh
=== Configuration ===
--es: http://127.0.0.1:9200
--index: dga
--webhook: https://hooks.slack.com/services/XXX
--zeekdns: /opt/zeek/logs/current/dns.log
--txtlog: /home/admin/dgalog.txt
--timezone: Asia/Seoul
=== Configuration ===

Successfully monitoring /opt/zeek/logs/current/dns.log...

=======================
timestamp: 2022년 12월 01일 04시 21분 49.381923
query: naver.com
prob: 0.0015445054
uid: CVlJrl2NjOiyAFLdB9
id.orig_h+p: 192.168.0.1:54212
id.resp_h+p: 1.1.1.1:53
qtype_name: -
answers: 321.456.789.0
=======================

=======================
timestamp: 2022년 12월 01일 04시 22분 47.710369
query: nbnmep.com
prob: 0.5765742
uid: CwYEnU2gvOFRo5rq3k
id.orig: 192.168.0.1:52323
id.resp: 1.1.1.1:53
qtype_name: -
answers: 123.456.789.0
=======================

DGA Domain Detected: nbnmep.com
[WHOIS Domain] Creation Date: 2020-07-07 18:11:25
[WHOIS Domain] Expiration Date: 2023-07-07 18:11:25
[WHOIS Domain] Updated Date: 2022-07-08 07:28:16
[WHOIS Domain] Registrar: Verisign Security and Stability
[WHOIS Domain] Name Servers: SC-A.SINKHOLE.SHADOWSERVER.ORG,
SC-B.SINKHOLE.SHADOWSERVER.ORG,
SC-C.SINKHOLE.SHADOWSERVER.ORG,
SC-D.SINKHOLE.SHADOWSERVER.ORG
[WHOIS IP] Country: US

```
