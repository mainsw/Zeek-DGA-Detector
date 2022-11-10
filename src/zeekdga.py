#!python3
# -*- coding: utf-8 -*-

from zat import zeek_log_reader
from dgaintel import get_prediction
from dgaintel import get_prob
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import os
from slack_sdk.webhook import WebhookClient
from datetime import datetime
import argparse


##### Configuration START #####

# 인스턴스 생성
parser = argparse.ArgumentParser(description='프로그램 작동을 위한 인자를 다음과 같이 설정해 주세요.')

# 입력받을 인자 설정
parser.add_argument('--es',        type=str,   default="http://127.0.0.1:9200", help="Elasticsearch 연결 설정 (default: http://127.0.0.1:9200)")
parser.add_argument('--index',     type=str,   default="dga", help="Elasticsearch Index Name 설정 (default: dga)")
parser.add_argument('--zeekdns',   type=str,   default="/opt/zeek/logs/current/dns.log", help="Zeek current/dns.log 경로 설정 (default: /opt/zeek/logs/current/dns.log)")
parser.add_argument('--txtlog',    type=str, help="[required] DGA 도메인 탐지 txt 로그 경로 설정 (ex: /home/admin/dgalog.txt)", required=True)
parser.add_argument('--webhook',   type=str, help="[required] Slack Webhook URL 설정 (ex: https://hooks.slack.com/services/XXX)", required=True)

# args 에 위 내용 저장
args = parser.parse_args()

# 입력받은 인자 출력
print("=== Configuration ===")
print("--es: "+args.es)
print("--index: "+args.index)
print("--webhook: "+args.webhook)
print("--zeekdns: "+args.zeekdns)
print("--txtlog: "+args.txtlog)
print("=== Configuration ===\n")

# Elasticsearch 연결 설정 (본인 환경에 맞게 수정)
es = Elasticsearch(args.es)

# Elasticsearch Index Name 설정 (수정 가능, 중복되지 않도록 설정)
index_name = args.index

# Slack Webhook 설정 (본인 환경에 맞게 수정)
webhook = WebhookClient(args.webhook)

# Zeek dns.log 경로 설정 (본인 환경에 맞게 수정)
dnsLogPath = args.zeekdns

# DGA 도메인 탐지 txt 로그 경로 설정 (본인 환경에 맞게 수정)
dgaTxtPath = args.txtlog

##### Configuration END #####

# DGA 도메인 탐지 txt 로그 파일 생성, 이미 있는 경우 pass
def make_txt(dgaTxtPath):
    if (os.path.isfile(dgaTxtPath)):
        pass
    else:
        f = open(dgaTxtPath, 'w')
        f.close()
make_txt(dgaTxtPath)

# Elasticsearch Index 생성, 이미 있는 경우 pass
def make_index(es, index_name):
    if es.indices.exists(index=index_name):
        pass
    else:
        es.indices.create(index=index_name)
make_index(es, index_name)

# Zeek dns.log 줄마다 반복하여 읽기.
reader = zeek_log_reader.ZeekLogReader(dnsLogPath, tail=True)
for row in reader.readrows():
    query = row['query']  
    timestamp = row['ts']
    uid = row['uid']
    prob = get_prob(query)
    probStr = str(prob)
    tsStr = timestamp.strftime("%Y년 %m월 %d일 %H시 %M분 %S.%f")
    print("\n=======================")
    print("query: "+query)
    print("prob: "+prob)
    print("uid: "+uid)
    print("=======================\n")
    
    # query (도메인) 데이터의 딥러닝 예측 결과, DGA 도메인 확률이 0.5 이상인 경우
    if prob>=0.5:
        print("DGA Domain Detected: "+query)
        
        # dga.txt에 DGA 탐지 기록
        f = open(dgaTxtPath, "a")
        f.write("query: "+query)
        f.write("\n")
        f.write(f"timestamp: {timestamp}")
        f.write("\n")
        f.write(f"probability: {prob}")
        f.write("\n")
        f.write("uid: "+uid)
        f.write("\n")
        f.write("\n")
        f.close()
        
        # Elasticsearch에 DGA 탐지 기록
        doc1 = {'query': query, 'timestamp': timestamp, 'probability': prob, 'uid': uid}
        es.index(index=index_name, doc_type='string', body=doc1)
        
        # Slack Webhook을 통해 DGA 탐지 경고 알림
        response = webhook.send(
            text="DGA Alert",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "=== DGA Domain Detected ===\n"+"query: "+query+"\nprob: "+probStr+"\nuid: "+uid+"\nts: "+tsStr+"\n========================="
                    }
                }
            ]
        )
        assert response.status_code == 200
        assert response.body == "ok"

