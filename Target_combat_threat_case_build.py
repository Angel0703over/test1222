import pandas as pd
import random
from base import LLMClient
from prompt.prompt_loader import PromptLoader
from util import response_extractor
import time
from tqdm import tqdm  # 导入进度条库


def generate(path, sheet_name, llm, target_sheet=None):
    """
    使用大模型生成目标作战威胁案例（随机选择一个核心维度）
    :return:
    """
    fight_threat_cases = []
    # 读取威胁源数据（A列）
    df = pd.read_excel(path, sheet_name=sheet_name, header=None, usecols='A')
    threat_sources = df.squeeze().tolist()

    # 随机挑选1/10的威胁源（向上取整至少保留1个）
    # sample_size = max(1, len(threat_sources) // 10)
    # sampled_threats = random.sample(threat_sources, sample_size)

    # 威胁案例生成的核心维度
    threat_dimensions = [
        "威胁发生的典型场景与环境特征",
        "威胁可能造成的作战影响与后果",
        "威胁的表现形式与识别特征",
        "应对该威胁的常见作战措施"
    ]

    # 使用tqdm创建进度条，遍历采样的威胁源
    for i, threat in enumerate(tqdm(threat_sources, desc="处理威胁案例")):
        random_dimension = random.choice(threat_dimensions)

        json_reply = llm.infer(
            system_prompt='你是目标作战威胁案例生成专家',
            user_prompt=PromptLoader.get_prompt(
                prompt_name='db/Target_combat_case.prompt',
                combat_lib=threat,
                dimension=random_dimension
            )
        )
        result = response_extractor(json_reply).get('result')
        if result:
            fight_threat_cases.append(result)

        # # 保存当前进度
        write_data_to_excel(
            arr=fight_threat_cases,
            path=path,
            sheet_name=target_sheet,
            append=False
        )
        time.sleep(3)  # 控制请求频率


def write_data_to_excel(arr, path, sheet_name, append=False):
    df = pd.DataFrame(arr, columns=['目标作战威胁案例'])
    if append:
        try:
            existing_df = pd.read_excel(path, sheet_name=sheet_name, header=None)
            df = pd.concat([existing_df, df], ignore_index=True)
        except (FileNotFoundError, ValueError):
            pass

    with pd.ExcelWriter(path, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False, header=False)



if __name__ == '__main__':
    PromptLoader.from_paths(['./prompt'])
    llm = LLMClient(
        llm_config={
            "api_key": "sk-25e969cec8f7407b9ad1ddd7686b940c",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "generate_config": {
                "temperature": 0.4,
            }
        },
    )
    generate(
        path='./resource/level_3.xlsx',
        # sheet_name='combat_threat_lib',
        sheet_name='抽取的威胁源',
        target_sheet='目标作战威胁案例',
        llm=llm
    )

