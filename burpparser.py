import csv
from xml.dom import minidom
import base64
from urllib.parse import parse_qs
from typing import Dict


# def parse_request_gpt(request_str):
#     request_dict = {}
#     headers_end = request_str.index('\r\n\r\n')
#     headers_str = request_str[:headers_end]
#     body_str = request_str[headers_end+4:]
#     headers_list = headers_str.split('\r\n')
#     request_dict['method'], request_dict['url'], request_dict['version'] = headers_list[0].split(
#         ' ')
#     request_dict['headers'] = {}
#     for header in headers_list[1:]:
#         header_parts = header.split(': ')
#         request_dict['headers'][header_parts[0]] = header_parts[1]
#     request_dict['body'] = body_str
#     return request_dict


def parse_request_gpt(request_str):
    request_dict = {}
    headers_end = request_str.index('\r\n\r\n')
    headers_str = request_str[:headers_end]
    body_str = request_str[headers_end+4:]
    headers_list = headers_str.split('\r\n')
    request_dict['method'], request_dict['url'], request_dict['version'] = headers_list[0].split(' ')
    request_dict['headers'] = {}
    for header in headers_list[1:]:
        header_parts = header.split(': ')
        request_dict['headers'][header_parts[0]] = header_parts[1]
    request_dict['body'] = body_str
    return request_dict

# def writerequest_to_csv(request_dict):
#     with open('requests_parsed.csv', 'w', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow(['method', 'url', 'version'])
#         writer.writerow([request_dict['method'], request_dict['url'], request_dict['version']])
#         writer.writerow([])
#         writer.writerow(['Header', 'Value'])
#         for key, value in request_dict['headers'].items():
#             writer.writerow([key, value])
#         writer.writerow([])
#         writer.writerow(['Body'])
#         writer.writerow([request_dict['body']])

def writerequest_to_csv(request_dict):
    with open('parsed_requests.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(['method', 'url', 'version', 'headers', 'body'])
        writer.writerow([request_dict['method'], request_dict['url'], request_dict['version'], request_dict['headers'], request_dict['body']])


def parse_burp_logs(log_file, output_file):
    with open(log_file, 'r') as f:
        dom = minidom.parse(f)
        items = dom.getElementsByTagName('item')
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Time', 'URL', 'IP Address', 'Port', 'Method',
                            'Path', 'Extension', 'Request', 'Status', 'Response', 'method', 'url', 'version', 'headers', 'body', 'count_single_quote','count_double_quote','count_backslash','count_backtick','count_dash','count_round_brackets','count_curly_brackets','count_sq_brackets','count_ang_brackets','count_forwardslash','count_equals','count_bad_words'])
            for item in items:

                time = item.getElementsByTagName(
                    'time')[0].firstChild.nodeValue
                url = item.getElementsByTagName('url')[0].firstChild.nodeValue
                ip_address = item.getElementsByTagName(
                    'host')[0].getAttribute('ip')
                port = item.getElementsByTagName(
                    'port')[0].firstChild.nodeValue
                method = item.getElementsByTagName(
                    'method')[0].firstChild.nodeValue
                path = item.getElementsByTagName(
                    'path')[0].firstChild.nodeValue
                extension = item.getElementsByTagName(
                    'extension')[0].firstChild.nodeValue
                request = item.getElementsByTagName(
                    'request')[0].firstChild.nodeValue
                status = item.getElementsByTagName(
                    'status')[0].firstChild.nodeValue
                response = item.getElementsByTagName(
                    'response')[0].firstChild.nodeValue

                request_decoded = base64.b64decode(request)
                request_decoded = request_decoded.decode('utf-8')
                response_decoded = base64.b64decode(response)
                response_decoded = response_decoded.decode('utf-8')

                request_dict = parse_request_gpt(request_decoded)
                response_dict = parse_request_gpt(response_decoded)
                # print(response_dict)
                
                # calculate single quote, double quote, backslash, backtick, dash, brackets and other characters used in attacks like SQLi, XSS, etc.
                count_single_quote = request_decoded.count("'")
                count_double_quote = request_decoded.count('"')
                count_backslash = request_decoded.count('\\')
                count_backtick = request_decoded.count('`')
                count_dash = request_decoded.count('--')
                count_round_brackets = request_decoded.count('(')
                count_round_brackets += request_decoded.count(')')
                count_curly_brackets = request_decoded.count('{')
                count_curly_brackets += request_decoded.count('}')
                count_sq_brackets = request_decoded.count('[')
                count_sq_brackets += request_decoded.count(']')
                count_ang_brackets = request_decoded.count('<')
                count_ang_brackets += request_decoded.count('>')
                count_forwardslash = request_decoded.count('/')
                count_equals = request_decoded.count('=')

                # form a list of common words used in attacks like SQLi, XSS, etc.
                bad_words = ['select', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'table', 'from', 'where', 'and', 'or', 'union', 'join', 'having', 'group', 'by', 'order', 'limit', 'offset', 'into', 'values', 'set', 'like', 'script', 'alert', 'onload', 'onerror', 'onmouseover', 'onmouseout', 'onfocus', 'onblur', 'onchange', 'onsubmit', 'onreset', 'onselect', 'onunload', 'onkeydown', 'onkeypress', 'onkeyup', 'img', 'src', 'href', 'url']

                # count the number of bad words in the request (case insensitive)
                count_bad_words = 0
                for word in bad_words:
                    count_bad_words += request_decoded.lower().count(word)

                writer.writerow([time, url, ip_address, port, method,
                                path, extension, request, status, response, request_dict['method'], request_dict['url'], request_dict['version'], request_dict['headers'], request_dict['body'], count_single_quote, count_double_quote, count_backslash, count_backtick, count_dash, count_round_brackets, count_curly_brackets, count_sq_brackets, count_ang_brackets, count_forwardslash, count_equals, count_bad_words])


parse_burp_logs("normalTrafficTraining.txt", "trainingdata_csic.csv")

