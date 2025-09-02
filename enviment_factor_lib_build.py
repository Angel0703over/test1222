# coding=utf-8
# @Time : 2025/8/16 11:02
# @Author : RoseLee
# @File : enviment_factor_lib_build
# @Project : threat-assessment
# @Description :
import pandas as pd
import random
import re
from itertools import product
from util import write_data_to_excel


def parse_range(range_str):
    ranges = []
    range_parts = re.findall(r'\([^)]+\)', range_str)

    for part in range_parts:
        part = part.strip('()')
        start, end = part.split(',')
        start = start.strip()
        end = end.strip()

        if start == '~':
            start_val = -float('inf')
            end_val = float(end)
        elif end == '~':
            start_val = float(start)
            end_val = float('inf')
        else:
            start_val = float(start)
            end_val = float(end)

        ranges.append((start_val, end_val))

    return ranges


def generate_value(ranges):
    """根据范围生成随机值"""
    values = []
    for (start, end) in ranges:
        if start == -float('inf'):
            value = round(random.uniform(end - 5, end - 0.1), 1)
        elif end == float('inf'):
            value = round(random.uniform(start + 0.1, start + 5), 1)
        else:
            value = round(random.uniform(start + 0.1, end - 0.1), 1)
        values.append(value)
    return values


def process_sheet(df, sheet_name):
    """处理单个sheet，生成该sheet的所有威胁等级描述和JSON数据"""
    sheet_results = []

    for _, row in df.iterrows():
        ranges = parse_range(row['value'])
        values = generate_value(ranges)

        if 'desp' in df.columns and pd.notna(row['desp']):
            descriptors = row['desp'].split(',')
        else:
            descriptors = [f"{sheet_name}{i + 1}" if len(values) > 1 else sheet_name
                           for i in range(len(values))]

        desc_parts = [f"{desc}{val}{row['units']}" for desc, val in zip(descriptors, values)]
        text_desc = '，'.join(desc_parts) + f"，{sheet_name}威胁等级为：{row['level']}"

        sheet_json = {
            'level': row['level'],
            'level_value': int(row['level_value']),
            'units': row['units']
        }
        for desc, val in zip(descriptors, values):
            sheet_json[desc] = val

        sheet_results.append({
            'text': text_desc,
            'json': {sheet_name: sheet_json}
        })

    return sheet_results


def read_library_level(path, sheet_names):
    """读取库中不同属性分级内容并进行组合"""
    environment_situation_labels = []
    environment_situation_labels_json = []

    for sheet_idx, sheet_name in enumerate(sheet_names):
        df = pd.read_excel(path, sheet_name=sheet_name)
        sheet_results = process_sheet(df, sheet_name)

        if sheet_idx == 0:
            environment_situation_labels = [item['text'] for item in sheet_results]
            environment_situation_labels_json = [item['json'] for item in sheet_results]
        else:
            new_labels = []
            new_jsons = []
            for (existing_label, existing_json), new_item in product(
                    zip(environment_situation_labels, environment_situation_labels_json),
                    sheet_results
            ):
                combined_label = f"{existing_label}；{new_item['text']}"
                new_labels.append(combined_label)
                combined_json = {**existing_json,** new_item['json']}
                new_jsons.append(combined_json)
            environment_situation_labels = new_labels
            environment_situation_labels_json = new_jsons

    return environment_situation_labels, environment_situation_labels_json


if __name__ == "__main__":

    excel_path = "./resource/level.xlsx"
    # 要处理的sheet名称列表
    sheets = ['风速', '海水温度','降水', '海洋流速', '水深', '电磁干扰']
    labels, jsons = read_library_level(excel_path, sheets)
    # print(labels)
    print("文本描述结果：")
    for i, label in enumerate(labels):
        print(f"{i + 1}. {label}")

    # print(jsons)
    print("\n部分JSON数据结果：")
    for i, json_data in enumerate(jsons):
        print(f"{i + 1}. {json_data}")

    write_data_to_excel(labels, './resource/level.xlsx', 'lib')