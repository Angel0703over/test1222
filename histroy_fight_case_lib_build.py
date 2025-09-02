# coding=utf-8
# @Time : 2025/8/16 13:11
# @Author : RoseLee
# @File : histroy_fight_case_lib_build
# @Project : threat-assessment
# @Description :构建历史作战案例库
import time

import pandas as pd
from base import LLMClient
from prompt.prompt_loader import PromptLoader
from util import response_extractor
# 定义战术规则
tactical_rules = [
    """无人机/蜂群低空袭扰
由运输机远程投放 X-61A 与 ALTIUS-600 无人机/蜂群飞抵我方
航母战斗群上方，对我方防空系统、通信系统等实施袭扰，并通过规
模攻击消耗我方防空资源。""",
    """有人/无人协同压制打击
由 XQ-58A 隐身无人机作为“忠诚僚机”前置与 F-35C 隐身战斗机
协同对我方航母、驱逐舰与护卫舰实施打击，并抵近台岛对我台岛封
控区域实施打击。""",
    """驱逐舰、巡洋舰前出打击
1
在天基卫星、E-2D 等侦察预警系统的支撑下，1 艘提康德罗加巡
洋舰和 2 艘伯克级驱逐舰组成的舰艇编队，由 4 架 F/A-18E 飞机进行
空中掩护，前出至我航母战斗群以东区域。发射战斧 BGM109-V/a
反舰导弹和 LRSAM 远程反舰导弹对我护卫舰、驱逐舰及航母实施打
击，同时发射 BGM-109C/D 对我军台岛登陆部队实施打击。"""
]


def generate(path, sheet_name, llm, target_sheet=None):
    """
    使用大模型生成历史案例
    :return:
    """
    # try:
    #     existing_df = pd.read_excel(path, sheet_name=target_sheet, header=None)
    #     fight_history_cases = existing_df.squeeze().tolist()
    # except (FileNotFoundError, ValueError):
    #     fight_history_cases = []
    fight_history_cases = []
    df = pd.read_excel(path, sheet_name=sheet_name, header=None, usecols='A')
    cases = df.squeeze().tolist()

    for i, case in enumerate(cases):
        for tactical_rule in tactical_rules:
            json_reply = llm.infer(
                system_prompt='你是一个历史作战案例生成专家',
                user_prompt=PromptLoader.get_prompt(
                    prompt_name='db/case_generating.prompt',
                    lib=case,
                    tactical_rule=tactical_rule
                )
            )
            print(json_reply)
            result = response_extractor(json_reply).get('result')
            fight_history_cases.append(result)
            break

        # # 每个外层循环结束后保存一次
        # write_data_to_excel(
        #     arr=fight_history_cases,
        #     path=path,
        #     sheet_name=target_sheet,
        #     append=False
        # )
        # print(f"已完成案例{i + 1}的处理并保存")
        # time.sleep(5)

def write_data_to_excel(arr, path, sheet_name, append=False):
    df = pd.DataFrame(arr, columns=['data'])
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
    "api_key": "sk-2a55c974496640f49f829f92395ea919",
    "model": "deepseek-chat",
    "base_url": "https://api.deepseek.com",
    "generate_config": {
        "temperature": 0.4,
    }
},
    )
    generate(
        path='./resource/level.xlsx',
        sheet_name='环境威胁库',
        target_sheet='case',
        llm=llm
    )