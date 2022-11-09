from zat import zeek_log_reader
from dgaintel import get_prediction
from dgaintel import get_prob
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import os
from slack_sdk.webhook import WebhookClient
from datetime import datetime


##### Configuration START #####

# Elasticsearch 연결 설정 (본인 환경에 맞게 수정)
es = Elasticsearch('http://127.0.0.1:9200')
es.info()

# Elasticsearch Index Name 설정 (수정 가능, 중복되지 않도록 설정)
index_name = 'dga'

# Slack Webhook 설정 (본인 환경에 맞게 수정)
webhookUrl = "https://your.webhook.url"
webhook = WebhookClient(webhookUrl)

# Zeek dns.log 경로 설정 (본인 환경에 맞게 수정)
reader = zeek_log_reader.ZeekLogReader('/opt/zeek/logs/current/dns.log', tail=True)

# DGA 도메인 탐지 txt 로그 경로 설정 (본인 환경에 맞게 수정)
dgaTxtPath = "/home/admin/dga.txt"

##### Configuration END #####


# Elasticsearch Index 생성, 이미 있는 경우 pass
def make_index(es, index_name):
    if es.indices.exists(index=index_name):
        pass
    else:
        es.indices.create(index=index_name)
make_index(es, index_name)

# Zeek dns.log 줄마다 반복하여 읽기.
for row in reader.readrows():
    query = row['query']  
    timestamp = row['ts']
    uid = row['uid']
    prob = get_prob(query)
    probStr = str(prob)
    tsStr = timestamp.strftime("%Y년 %m월 %d일 %H시 %M분 %S.%f")
    print("\n=======================")
    print(query)
    print(prob)
    print(uid)
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
        f.write("uid "+uid)
        f.write("\n")
        f.write("\n")
        
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

