# coding=utf-8
# @Time : 2025/7/23 9:55
# @Author : RoseLee
# @File : utils
# @Project : fault-analysis
# @Description :

import json
import random
import re
import subprocess
import pandas as pd


def response_extractor(response):
    """
    提取大模型返回的json格式的结果
    :param response: 大模型返回的json格式的回复
    :return:
    """
    regex = r'```json\n(.*?)\n```'
    json_s = re.search(regex, response, re.DOTALL).group(1)
    result = json.loads(json_s)
    return result

def query_by_statement(statement):
    """
    执行传入的linux查询语句
    :param statement:
    :return:
    """
    result = subprocess.run(
        statement,
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()

def re_extractor(regex, content):
    """
    根据传入内容和正则表达式进行匹配并返回结果
    :param regex:
    :param content:
    :return:
    """
    a = re.compile(regex)
    match = a.search(content)
    if match:
        return match.groups()

def write_data_to_excel(arr, path, sheet_name):
    # 将数组转换为DataFrame（单列）
    df = pd.DataFrame(arr, columns=['data'])  # '数据'为列名，可根据需要修改

    # 创建ExcelWriter对象，确保写入时不覆盖其他工作表
    with pd.ExcelWriter(path, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
        # 写入数据到指定工作表
        df.to_excel(writer, sheet_name=sheet_name, index=False, header=False)


def add_level(path):
    """
    为案例库的每一条添加得分
    :param path:
    :return:
    """
    df = pd.read_excel(path, sheet_name='目标作战威胁库')
    cases = []
    for index, row in df.iterrows():
        threat_score = random.randint(6,12)
        score = row.iloc[0].count('一级威胁') * 1 + row.iloc[0].count('二级威胁') * 2 + threat_score
        case = row.iloc[0] + " 威胁分数为：" + str(score)
        cases.append(case)

    df = pd.DataFrame(cases)
    with pd.ExcelWriter(path, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
        df.to_excel(writer, sheet_name='目标作战威胁库(分数)', index=False)
    # df.to_excel(path, sheet_name='目标作战威胁库(分数)')


if __name__ == '__main__':
    add_level('./resource/level_3.xlsx')
    # pass

