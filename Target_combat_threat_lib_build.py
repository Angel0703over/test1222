# coding=utf-8
# @Time : 2025/8/26 10:00
# @Author : Your Name
# @File : combat_threat_lib_build.py
# @Project : threat-assessment
# @Description : 基于level_3.xlsx生成目标作战威胁库
import pandas as pd
import random
import re
from itertools import product
from util import write_data_to_excel  # 复用原工具函数（需确保util.py存在）


def parse_range_or_text(range_or_text_str):
    """
    适配level_3.xlsx：解析数值范围（含[]区间）或直接返回文本（如目标种类、武器配置）
    :param range_or_text_str: 单元格内容（可能是数值范围如"(0,5)"，也可能是文本如"非战斗平台"）
    :return: 若为范围返回解析后的范围列表，若为文本返回原文本
    """
    # 匹配数值范围格式（支持()和[]）
    range_pattern = r'[\(\[][^)\]]+[\)\]]'
    if re.match(range_pattern, str(range_or_text_str).strip()):
        ranges = []
        # 提取所有(...)或[...]格式的区间
        range_parts = re.findall(range_pattern, range_or_text_str)
        for part in range_parts:
            # 去除首尾的括号/方括号
            part_clean = part.strip('()[]')
            start, end = part_clean.split(',')
            start = start.strip()
            end = end.strip()

            # 处理无限区间（~表示）
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
    else:
        # 非范围格式（如文本描述），直接返回原内容
        return str(range_or_text_str).strip()


def generate_value_or_text(input_data):
    """
    适配level_3.xlsx：若为范围则生成随机值，若为文本则直接返回
    :param input_data: parse_range_or_text的输出（范围列表或文本）
    :return: 生成的数值列表（范围场景）或原文本（文本场景）
    """
    # 若为范围列表，生成随机值
    if isinstance(input_data, list) and all(isinstance(item, tuple) for item in input_data):
        values = []
        for (start, end) in input_data:
            if start == -float('inf'):
                # 向下扩展5个单位（如(~,5)→0~4.9）
                value = round(random.uniform(end - 5, end - 0.1), 1)
            elif end == float('inf'):
                # 向上扩展5个单位（如(15,~)→15.1~20）
                value = round(random.uniform(start + 0.1, start + 5), 1)
            else:
                # 普通区间（避开边界值）
                value = round(random.uniform(start + 0.1, end - 0.1), 1)
            values.append(value)
        return values
    # 若为文本，直接返回
    else:
        return [input_data]  # 用列表包装，统一后续迭代格式


def process_sheet(df, sheet_name):
    """
    适配level_3.xlsx：处理单个作战威胁要素sheet（支持文本型要素、无单位场景）
    :param df: 单个sheet的DataFrame
    :param sheet_name: sheet名称（如"杀伤链响应速度"）
    :return: 包含文本描述和JSON数据的列表
    """
    sheet_results = []
    for _, row in df.iterrows():
        # 1. 解析value列（可能是范围或文本）
        input_data = parse_range_or_text(row['value'])
        # 2. 生成值（范围→随机数，文本→原内容）
        values = generate_value_or_text(input_data)

        # 3. 处理描述符（desp列，无则用sheet名称）
        if 'desp' in df.columns and pd.notna(row['desp']):
            # 用desp的前半部分作为描述（如"衡量从发现目标到完成打击的时间效率"→简化为"杀伤链响应速度"）
            descriptors = [sheet_name]  # 统一用sheet名作为描述符，更简洁
        else:
            # 多值场景（理论上level_3无多值，此处兼容）
            descriptors = [f"{sheet_name}{i + 1}" if len(values) > 1 else sheet_name
                           for i in range(len(values))]

        # 4. 生成文本描述（适配无单位场景）
        units = row['units'] if pd.notna(row['units']) and row['units'] != '无' else ''
        desc_parts = [f"{desc}：{val}{units}" for desc, val in zip(descriptors, values)]
        text_desc = '，'.join(desc_parts) + f"，{sheet_name}威胁等级为：{row['level']}"

        # 5. 生成JSON数据（包含等级、数值、单位）
        sheet_json = {
            'level': row['level'],
            'level_value': int(row['level_value']),
            'units': units  # 无单位时存空字符串，避免键缺失
        }
        for desc, val in zip(descriptors, values):
            sheet_json[desc] = val  # 文本型要素直接存文本，数值型存随机数

        sheet_results.append({
            'text': text_desc,
            'json': {sheet_name: sheet_json}
        })
    return sheet_results


def read_combat_library_level(path, sheet_names):
    """
    读取level_3.xlsx的作战威胁要素，生成所有要素组合的威胁库
    :param path: Excel文件路径
    :param sheet_names: 需要处理的sheet名称列表（对应作战威胁要素）
    :return: 组合后的文本描述列表、JSON数据列表
    """
    combat_threat_labels = []  # 威胁场景文本描述
    combat_threat_jsons = []   # 威胁场景结构化数据
    for sheet_idx, sheet_name in enumerate(sheet_names):
        # 读取单个sheet（确保Excel中sheet名与列表完全一致）
        df = pd.read_excel(path, sheet_name=sheet_name)
        # 处理当前sheet，生成单要素结果
        sheet_results = process_sheet(df, sheet_name)

        # 首次处理：直接初始化列表
        if sheet_idx == 0:
            combat_threat_labels = [item['text'] for item in sheet_results]
            combat_threat_jsons = [item['json'] for item in sheet_results]
        # 后续处理：与已有结果做笛卡尔积（所有要素组合）
        else:
            new_labels = []
            new_jsons = []
            # 遍历已有组合与新要素，生成所有可能的威胁场景
            for (existing_label, existing_json), new_item in product(
                    zip(combat_threat_labels, combat_threat_jsons),
                    sheet_results
            ):
                # 组合文本描述（用分号分隔不同要素）
                combined_label = f"{existing_label}；{new_item['text']}"
                # 组合JSON数据（合并字典）
                combined_json = {**existing_json, **new_item['json']}
                new_labels.append(combined_label)
                new_jsons.append(combined_json)
            # 更新为新组合
            combat_threat_labels = new_labels
            combat_threat_jsons = new_jsons
    return combat_threat_labels, combat_threat_jsons


if __name__ == "__main__":
    # -------------------------- 配置参数 --------------------------
    EXCEL_PATH = "./resource/level_3.xlsx"  # level_3.xlsx的路径（需确保resource文件夹存在）
    # 作战威胁要素sheet列表（与level_3.xlsx中的sheet名完全一致）
    COMBAT_SHEETS = [
        '杀伤链响应速度', '杀伤链闭合概率', '支援到达时间', '协同打击系数',
        '目标种类', '武器配置', '干扰能力', '协作模式', '后援系统', '作战续航'
    ]
    OUTPUT_SHEET_NAME = 'combat_threat_lib'  # 结果写入Excel的sheet名
    # --------------------------------------------------------------

    # 1. 生成作战威胁库（文本描述+JSON数据）
    threat_labels, threat_jsons = read_combat_library_level(EXCEL_PATH, COMBAT_SHEETS)

    # 2. 打印结果（可选，用于调试）
    print("=== 目标作战威胁库文本描述（前10条） ===")
    for i, label in enumerate(threat_labels[:10]):  # 仅打印前10条，避免输出过长
        print(f"{i + 1}. {label}")

    print("\n=== 目标作战威胁库JSON数据（前2条） ===")
    for i, json_data in enumerate(threat_jsons[:2]):
        print(f"{i + 1}. {json_data}")

    # 3. 写入Excel（需确保util.py中的write_data_to_excel函数支持写入列表+JSON）
    # 若原write_data_to_excel仅支持文本，可替换为下方注释的pandas写入逻辑
    try:
        write_data_to_excel(
            data=[[label, str(json_data)] for label, json_data in zip(threat_labels, threat_jsons)],
            path=EXCEL_PATH,
            sheet_name=OUTPUT_SHEET_NAME
        )
        print(f"\n✅ 威胁库已成功写入Excel：{EXCEL_PATH} -> {OUTPUT_SHEET_NAME}")
    except Exception as e:
        # 备用写入逻辑（若util函数不兼容）
        df_output = pd.DataFrame({
            '威胁场景描述': threat_labels,
            '结构化JSON数据': [str(json_data) for json_data in threat_jsons]
        })
        with pd.ExcelWriter(EXCEL_PATH, mode='a', engine='openpyxl', if_sheet_exists='replace') as writer:
            df_output.to_excel(writer, sheet_name=OUTPUT_SHEET_NAME, index=False)
        print(f"\n✅ 备用逻辑：威胁库已成功写入Excel：{EXCEL_PATH} -> {OUTPUT_SHEET_NAME}")