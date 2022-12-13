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
import pytz
import whois
import json
import pprint


##### Configuration START #####

pp = pprint.PrettyPrinter(indent=4)

# Timezone List
pp.pprint("=== Timezones ===")
pp.pprint(pytz.all_timezones)

# 인스턴스 생성
parser = argparse.ArgumentParser(description='프로그램 작동을 위한 인자를 다음과 같이 설정해 주세요.')

# 입력받을 인자 설정
parser.add_argument('--es',        type=str,   default="http://127.0.0.1:9200", help="Elasticsearch 연결 설정 (default: http://127.0.0.1:9200)")
parser.add_argument('--index',     type=str,   default="dga", help="Elasticsearch Index Name 설정 (default: dga)")
parser.add_argument('--zeekdns',   type=str,   default="/opt/zeek/logs/current/dns.log", help="Zeek current/dns.log 경로 설정 (default: /opt/zeek/logs/current/dns.log)")
parser.add_argument('--txtlog',    type=str, help="[required] DGA 도메인 탐지 txt 로그 경로 설정 (ex: /home/admin/dgalog.txt)", required=True)
parser.add_argument('--webhook',   type=str, help="[required] Slack Webhook URL 설정 (ex: https://hooks.slack.com/services/XXX)", required=True)
parser.add_argument('--timezone',  type=str, help="[required] 현재 Timezone 설정, 상단에 출력된 리스트 참조 (ex: Asia/Seoul)")

# args 에 위 내용 저장
args = parser.parse_args()

# 입력받은 인자 출력
print("=== Configuration ===")
print("--es: "+args.es)
print("--index: "+args.index)
print("--webhook: "+args.webhook)
print("--zeekdns: "+args.zeekdns)
print("--txtlog: "+args.txtlog)
print("--timezone: "+args.timezone)
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

# Timezone Conversion
tz = pytz.timezone(args.timezone)
def toUTC(d):
    return tz.normalize(tz.localize(d)).astimezone(pytz.utc)

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
    origIP = row['id.orig_h']
    origPORT = row['id.orig_p']
    respIP = row['id.resp_h']
    respPORT = row['id.resp_p']
    qtype = row['qtype_name']
    answers = row['answers']
    prob = get_prob(query)
    probStr = str(prob)
    tsStr = timestamp.strftime("%Y년 %m월 %d일 %H시 %M분 %S.%f")
    tsUTC = toUTC(timestamp)
    print("\n=======================")
    print("timestamp: "+tsStr)
    print("query: "+query)
    print("prob: "+probStr)
    print("uid: "+uid)
    print("id.orig_h+p: "+origIP+":"+str(origPORT))
    print("id.resp_h+p: "+respIP+":"+str(respPORT))
    print("qtype_name: "+qtype)
    print("answers: "+answers)
    print("=======================\n")
    
    # query (도메인) 데이터의 딥러닝 예측 결과, DGA 도메인 확률이 0.5 이상인 경우
    if prob>=0.5:
        print("DGA Domain Detected: "+query)
        whoisQuery = whois.whois(query)
        whoisIPQuery = whois.whois(answers)
        # whoisQueryStr = json.dumps(whoisQuery)
        # print(whoisQuery)

        # datetime이 list로 여러개인 경우, 가장 최신 데이터로 변환
        if isinstance(whoisQuery.expiration_date, list):
            whoisQuery.update(expiration_date=whoisQuery.expiration_date[-1])
        if isinstance(whoisQuery.creation_date, list):
            whoisQuery.update(creation_date=whoisQuery.creation_date[-1])
        if isinstance(whoisQuery.updated_date, list):
            whoisQuery.update(updated_date=whoisQuery.updated_date[-1])
        if isinstance(whoisQuery.name_servers, list):
            whoisQuery.update(name_servers=','.join(whoisQuery.name_servers))

        # None일 경우 String "None"으로 변환
        def xstr(s):
            if s is None:
                return 'None'
            return str(s)

        whoisCrDate = xstr(whoisQuery.creation_date)
        whoisExDate = xstr(whoisQuery.expiration_date)
        whoisUpDate = xstr(whoisQuery.updated_date)
        whoisRegistrar = xstr(whoisQuery.registrar)
        whoisNameServers = xstr(whoisQuery.name_servers)
        whoisIPCountry = xstr(whoisIPQuery.country)
        
        print(f"[WHOIS Domain] Creation Date: {whoisCrDate}")
        print(f"[WHOIS Domain] Expiration Date: {whoisExDate}")
        print(f"[WHOIS Domain] Updated Date: {whoisUpDate}")
        print("[WHOIS Domain] Registrar: "+ whoisRegistrar)
        print("[WHOIS Domain] Name Servers: "+ whoisNameServers)
        print("[WHOIS IP] Country: "+ whoisIPCountry)
        
        # dga.txt에 DGA 탐지 기록
        f = open(dgaTxtPath, "a")
        f.write("query: "+query)
        f.write("\n")
        f.write(f"timestamp: {tsStr}")
        f.write("\n")
        f.write(f"probability: {prob}")
        f.write("\n")
        f.write("uid: "+uid)
        f.write("\n")
        f.write("id.orig_h: "+origIP)
        f.write("\n")
        f.write("id.resp_h: "+respIP)
        f.write("\n")
        f.write("id.orig_p: "+str(origPORT))
        f.write("\n")
        f.write("id.resp_p: "+str(respPORT))
        f.write("\n")
        f.write("qtype_name: "+qtype)
        f.write("\n")
        f.write("answers: "+answers)
        f.write("\n")
        f.write(f"[WHOIS Domain] Creation Date: {whoisCrDate}")
        f.write("\n")
        f.write(f"[WHOIS Domain] Expiration Date: {whoisExDate}")
        f.write("\n")
        f.write(f"[WHOIS Domain] Updated Date: {whoisUpDate}")
        f.write("\n")
        f.write("[WHOIS Domain] Registrar: "+whoisRegistrar)
        f.write("\n")
        f.write("[WHOIS Domain] Name Servers: "+whoisNameServers)
        f.write("\n")
        f.write("[WHOIS IP] Country: "+whoisIPCountry)
        f.write("\n")
        f.write("\n")
        f.close()
        
        # Elasticsearch에 DGA 탐지 기록
        doc1 = {'query': query, 'timestamp': tsUTC, 'probability': probStr, 'uid': uid, 'id.orig_h': origIP, 'id.resp_h': respIP, 'qtype_name': qtype, 'answers': answers, 'whois_domain_creation_date': whoisQuery.creation_date, 'whois_domain_expiration_date': whoisQuery.expiration_date, 'whois_domain_registrar': whoisQuery.registrar, 'whois_ip_country': whoisIPCountry, 'whois_domain_updated_date': whoisQuery.updated_date, 'whois_domain_name_servers': whoisNameServers, 'id.orig_p': origPORT, 'id.resp_p': respPORT}
        es.index(index=index_name, doc_type='string', body=doc1)
        
        # Slack Webhook을 통해 DGA 탐지 경고 알림
        response = webhook.send(
            text="DGA Alert",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text":"=== DGA Domain Detected ===\n"
                        +"query: "+query+
                        "\nprob: "+probStr+
                        "\nuid: "+uid+
                        "\nts: "+tsStr+
                        "\nid.orig_h+p: "+origIP+":"+str(origPORT)+
                        "\nid.resp_h+p: "+respIP+":"+str(respPORT)+
                        "\nqtype_name: "+qtype+
                        "\nanswers: "+answers+
                        "\n[WHOIS Domain] Creation date: "+str(whoisCrDate)+
                        "\n[WHOIS Domain] Expiration date: "+str(whoisExDate)+
                        "\n[WHOIS Domain] Updated date: "+str(whoisUpDate)+
                        "\n[WHOIS Domain] Registrar: "+str(whoisRegistrar)+
                        "\n[WHOIS Domain] Name Servers: "+str(whoisNameServers)+
                        "\n[WHOIS IP] Country: "+str(whoisIPCountry)+
                        "\n========================="
                    }
                }
            ]
        )
        assert response.status_code == 200
        assert response.body == "ok"

