# coding=utf-8
# @Time :
# @Author :
# @File : rag_score_average
# @Project : threat-assessment
# @Description : 从三个向量数据库获取分数并计算平均值

import os
import re
from typing import List, Tuple
from tqdm import tqdm
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.vectorstores import FAISS
from langchain.tools.retriever import create_retriever_tool
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_community.embeddings import DashScopeEmbeddings
from langchain.chat_models import init_chat_model

# 导入本地模块
from prompt.prompt_loader import PromptLoader
from base import LLMClient
import configs
from configs import DeepSeek_API_KEY, Dashscope_Api_Key
from util import response_extractor

# 环境变量配置
os.environ["DEEPSEEK_API_KEY"] = DeepSeek_API_KEY

# 常量定义
VECTOR_DBS = {
    "environment": "environment_db",
    "space": "space_db",
    "combat": "combat_db"
}
EMBEDDING_MODEL = "text-embedding-v4"
DEFAULT_K = 1  # 每个数据库返回的相似案例数


def get_conversational_chain(tools: List, question: str) -> dict:
    """使用agent执行检索任务"""
    try:
        llm = init_chat_model("deepseek-chat", model_provider="deepseek")
        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                """你是一个AI助手，请根据提供的上下文回答问题，确保提供所有细节，
                如果答案不在上下文中，请说"答案不在上下文中"，不要提供错误的答案""",
            ),
            ("placeholder", "{chat_history}"),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])

        agent = create_tool_calling_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
        return agent_executor.invoke({"input": question})
    except Exception as e:
        # print(f"对话链执行错误: {str(e)}")
        raise


def query_single_db(question: str, db_name: str) -> dict:
    """查询单个向量数据库"""
    db_path = VECTOR_DBS[db_name]
    try:
        # 加载指定的现有数据库
        db = FAISS.load_local(
            db_path,
            DashScopeEmbeddings(model=EMBEDDING_MODEL, dashscope_api_key=Dashscope_Api_Key),
            allow_dangerous_deserialization=True
        )
        retriever = db.as_retriever()
        retrieval_tool = create_retriever_tool(
            retriever,
            f"extractor_{db_name}",
            f"从{db_name}数据库的案例中查询信息"
        )
        return get_conversational_chain([retrieval_tool], question)
    except Exception as e:
        # print(f"查询数据库{db_name}失败: {str(e)}")
        raise


def get_db_similar_case(db_name: str, query_text: str) -> str:
    """从单个数据库获取最相似案例"""
    db_path = VECTOR_DBS[db_name]
    embeddings = DashScopeEmbeddings(
        model=EMBEDDING_MODEL,
        dashscope_api_key=Dashscope_Api_Key
    )

    try:
        db = FAISS.load_local(db_path, embeddings, allow_dangerous_deserialization=True)
        retriever = db.as_retriever(search_kwargs={"k": DEFAULT_K})
        similar_docs = retriever.invoke(query_text)
        return similar_docs[0].page_content if similar_docs else ""
    except Exception as e:
        # print(f"获取{db_name}相似案例失败: {str(e)}")
        return ""


def extract_score_from_response(response):
    """从响应中提取分数，支持自然语言格式"""
    # 确保我们处理的是字符串
    if isinstance(response, dict):
        response_text = response.get('output', '').strip()
    else:
        response_text = str(response).strip()

    # 使用正则表达式从文本中提取数字
    # 匹配整数或小数
    match = re.search(r'\b\d+\b', response_text)
    if match:
        return int(match.group())
    else:
        raise ValueError(f"无法从响应中提取分数: {response_text}")


def get_single_db_score(db_name: str, level_result: str) -> int:
    """获取单个数据库的威胁分数"""
    # 获取该数据库的相似案例
    similar_case = get_db_similar_case(db_name, level_result)
    if not similar_case:
        raise ValueError(f"数据库{db_name}未找到相似案例")

    prompt = PromptLoader.get_prompt(
        prompt_name='rag/final_score.prompt',
        db_type=db_name,
        similar_case_content=similar_case
    )
    response = query_single_db(prompt, db_name)
    # 处理错误标识
    response_text = response.get("output", "").strip()
    if response_text == "ERROR: INVALID_SIMILAR_CASE":
        raise ValueError(f"数据库{db_name}的相似案例格式错误：{similar_case}")
    # 提取分数
    return extract_score_from_response(response)


# def classify_level(description: str) -> str:
#     """对输入描述进行分级"""
#     try:
#         llm = LLMClient(configs.DEEPSEEK_V3_CONFIG)
#         return response_extractor(
#             llm.infer(
#                 system_prompt='你是一个分级专家',
#                 user_prompt=PromptLoader.get_prompt(
#                     prompt_name='rag/final.prompt',
#                     comprehensive_threat_description=description
#                 )
#             )
#         ).get("result", "")
#     except Exception as e:
#         # print(f"分级处理失败: {str(e)}")
#         return ""


def classify_level(description: str) -> str:
    """对输入描述进行分级，强化响应解析和错误处理，避免返回空字符串"""
    try:
        llm = LLMClient(configs.DEEPSEEK_V3_CONFIG)
        prompt = PromptLoader.get_prompt(
            prompt_name='rag/final.prompt',
            comprehensive_threat_description=description
        )

        llm_response = llm.infer(
            system_prompt='你是一个专业的海上多维度威胁分级专家，必须严格按照以下规则输出：\n'
                          '1. 仅输出包含"海洋环境威胁：""目标空间威胁：""目标作战威胁："的JSON格式结果，不添加任何多余文字；\n'
                          '2. 每个维度必须从输入描述中提取所有属性（如海水温度、风速、目标种类等）并分级，不遗漏；\n'
                          '3. 结果格式严格遵循：{"result":"海洋环境威胁：XXX；目标空间威胁：XXX；目标作战威胁：XXX"}',
            user_prompt=prompt,
        )
        extracted = response_extractor(llm_response)
        level_result = extracted["result"]
        return level_result
    except Exception as e:
        # 详细打印错误信息，便于定位问题
        error_msg = f"分级处理失败：{str(e)}"
        raise ValueError(error_msg)

def get_threat_score(environment_desp: str) -> str:
    """获取威胁分数主函数（三个数据库分数平均值）"""
    try:
        # 步骤1：威胁分级
        level_result = classify_level(description=environment_desp)
        if not level_result:
            return "错误：威胁分级结果为空"

        # 步骤2：从三个数据库分别获取分数
        scores = {}
        for db_name in VECTOR_DBS:
            score = get_single_db_score(db_name, level_result)
            scores[db_name] = score

        # 步骤3：计算平均值
        total = sum(scores.values())
        average_score = round(total / len(scores))

        result_lines = ["威胁评估结果："]
        for db_name, score in scores.items():
            result_lines.append(f"- {db_name}分数：{score}")
        result_lines.append(f"- 最终平均分数：{average_score}")

        return "\n".join(result_lines)

    except Exception as e:
        return f"获取威胁分数失败：{str(e)}"


def read_case_from_file(file_path: str) -> list:
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read().strip().replace('\r\n', '\n')
    raw_cases = re.split(r'\n+', content)
    clean_cases = []
    for case in raw_cases:
        if not case.strip():
            continue
        # 清理内容：
        cleaned = case.strip()
        cleaned = re.sub(r'[\u3000\u200b\t]', '', cleaned)  # 移除全角空格、零宽空格、制表符
        cleaned = re.sub(r'\s+', ' ', cleaned)  # 多个空格→单个空格（如“26 米 / 秒”中的多余空格）
        cleaned = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fa5\.\,\/\:\;\-\sV\/m]', '', cleaned)  # 保留有效字符，移除其他特殊符号
        clean_cases.append(cleaned)

    return clean_cases


if __name__ == '__main__':
    # 初始化提示词加载器
    PromptLoader.from_paths(['./prompt'])

    # case_file_path = 'case.txt'
    # test_cases = read_case_from_file(case_file_path)
    # for case in test_cases:
    #     result = get_threat_score(case)
    #     print(result)

    # 测试输入
    test_input = """
    西部某近岸海域，海水温度 10℃，25m/s 强风伴随 48 小时 180mm 降雨，海面流速 1.8m/s、水深 20m，中高频与超短波电磁干扰强度分别达 22V/m、18V/m。
    敌方通过运输机投放 30 架 X-61A 与 20 架 ALTIUS-600 无人机 / 蜂群，试图袭扰我方航母战斗群。无人机初始距航母 300km，抵近至 100km 时受干扰滞留，最终停留在 80km 处，巡航速度仅 0.3-0.6Ma，50 架无人机分散在 50km² 空域，密度低且编队松散，仅 X-61A 搭载少量炸药，受暴雨影响其光电传感器对我方舰艇覆盖率仅 35%。作战中，无人机依赖后方指令，干扰导致指令延迟 22 分钟，打击成功率降至 30%，后续支援需 40 分钟抵达，强风还使无人机续航从 4 小时缩至 2.5 小时。
    我方启动电子对抗系统，切断 60% 无人机通信，利用 800 米航线偏移布设警戒点，最终拦截 48 架，剩余 2 架因炸药引信受潮失效未造成损伤，防空资源消耗仅为常规的 15%。
    """
    print(get_threat_score(test_input))
