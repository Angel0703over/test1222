# coding=utf-8
# @Time : 2025/8/18 17:01
# @Author : RoseLee
# @File : rag_tools
# @Project : threat-assessment
# @Description :对文本进行向量化，进行威胁评估分数查询
import pandas as pd
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.vectorstores import FAISS
from langchain.tools.retriever import create_retriever_tool
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_community.embeddings import DashScopeEmbeddings
from langchain.chat_models import init_chat_model
import os
from prompt.prompt_loader import PromptLoader
from base import LLMClient
import configs
from configs import DeepSeek_API_KEY, Dashscope_Api_Key
from util import response_extractor
import re

from tqdm import tqdm

os.environ["DEEPSEEK_API_KEY"] = DeepSeek_API_KEY

BATCH_SIZE = 10
embeddings = DashScopeEmbeddings(
    model="text-embedding-v4", dashscope_api_key=Dashscope_Api_Key
)


def get_chunks(text: str):
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = text_splitter.split_text(text)
    return chunks


def vector_store(text_chunks: list):
    """将文本块分批次存储到FAISS向量数据库"""
    if not text_chunks:
        return False

    try:
        db = FAISS.load_local("combat_db", embeddings)
    except:
        first_batch = text_chunks[:BATCH_SIZE]
        db = FAISS.from_texts(first_batch, embedding=embeddings)
        remaining_chunks = text_chunks[BATCH_SIZE:]
    else:
        remaining_chunks = text_chunks

    # 分批次添加剩余的文本块，添加进度条
    total_batches = (len(remaining_chunks) + BATCH_SIZE - 1) // BATCH_SIZE
    for i in tqdm(range(0, len(remaining_chunks), BATCH_SIZE),
                  total=total_batches,
                  desc="存储向量数据"):
        batch = remaining_chunks[i:i + BATCH_SIZE]
        db.add_texts(batch)

    # 保存更新后的数据库
    db.save_local("combat_db")
    return True


def get_conversational_chain(tools, ques):
    """使用agent执行任务"""
    llm = init_chat_model("deepseek-chat", model_provider="deepseek")
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """你是一个AI助手，请根据提供的上下文回答问题，确保提供所有细节，如果答案不在上下文中，请说"答案不在上下文中"，不要提供错误的答案""",
        ),
        ("placeholder", "{chat_history}"),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    tool = [tools]
    agent = create_tool_calling_agent(llm, tool, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tool, verbose=True)

    response = agent_executor.invoke({"input": ques})
    print(response)
    return response


def query(question):
    """配置检索工具"""
    new_db = FAISS.load_local("combat_db", embeddings, allow_dangerous_deserialization=True)
    retriever = new_db.as_retriever()
    retrieval_chain = create_retriever_tool(retriever, "information_extractor",
                                            "This tool is to give answer to queries from the '历史作战案例库'")
    return get_conversational_chain(retrieval_chain, question)


def query_for_similarity(target_space_threat_description):
    """根据相似度查找对应案例"""
    db = FAISS.load_local("combat_db", embeddings, allow_dangerous_deserialization=True)
    retriever = db.as_retriever(search_kwargs={"k": 1})  # 只返回最相似的结果
    similar_docs = retriever.get_relevant_documents(target_space_threat_description)

    if not similar_docs:
        return "未找到相似案例"

    # 从最相似的案例中提取威胁分数
    most_similar_case = similar_docs[0].page_content
    score_match = re.search(r"威胁分数为：(\d+)", most_similar_case)
    if score_match:
        return f"最相似案例的威胁分数为：{score_match.group(1)}"
    else:
        return "未在相似案例中找到威胁分数"


def retrieval_data_storage(file_path: str, sheet_name: str):
    """从Excel文件读取数据并存储到向量数据库"""
    df = pd.read_excel(file_path, sheet_name=sheet_name, header=None)
    all_chunks = []

    # 为行处理添加进度条
    for index, row in tqdm(df.iterrows(), total=len(df), desc="读取Excel数据"):
        text = str(row[0])
        if text.strip():
            chunks = get_chunks(text)
            all_chunks.extend(chunks)

    return vector_store(all_chunks)


def classify_level(description: str) -> str:
    """对输入描述进行分级"""
    llm = LLMClient(configs.DEEPSEEK_V3_CONFIG)
    return response_extractor(
        llm.infer(
            system_prompt='你是一个分级专家',
            user_prompt=PromptLoader.get_prompt(
                prompt_name='rag/target_combat_classification.prompt',
                target_combat_threat_description=description
            )
        )
    ).get("result")





def get_threat_score(environment_desp):
    """获取威胁分数"""
    try:
        # 添加分级过程的进度提示
        with tqdm(total=1, desc="正在进行威胁分级") as pbar:
            level_result = classify_level(description=environment_desp)
            pbar.update(1)
        # 打印分级结果用于调试
        print(f"威胁分级结果: {level_result}")

        # 添加相似度查询的进度提示
        with tqdm(total=1, desc="正在查找相似案例") as pbar:
            target_space_threat = query_for_similarity(level_result)
            pbar.update(1)
        # 打印相似案例查询结果
        print(f"相似案例信息: {target_space_threat}")

        # 添加分数查询的进度提示
        with tqdm(total=1, desc="正在计算威胁分数") as pbar:
            prompt = PromptLoader.get_prompt(
                prompt_name='rag/target_combat_score.prompt',
                target_combat_threat=target_space_threat
            )
            response = query(prompt).get('output', '')
            pbar.update(1)
        # 打印原始响应用于调试
        print(f"LLM原始响应: {response}")

        # 增强正则匹配规则，允许空格和中英文标点差异
        score_match = re.search(r"威胁分数为\s*[:：]\s*(\d+)", response)
        if score_match:
            return score_match.group(1)
        else:
            # 未匹配到分数时返回明确提示
            return f"错误：未找到威胁分数。请检查输入格式或提示模板。"

    except Exception as e:
        # 捕获所有异常并返回错误信息
        return f"获取威胁分数失败：{str(e)}"


if __name__ == '__main__':
    # 存储指定的库
    retrieval_data_storage(file_path='./resource/level_3.xlsx', sheet_name='目标作战威胁库')

    PromptLoader.from_paths(['./prompt'])
    # 模拟生成的目标作战情况
    # input_str = """
    # 某海域作战行动中，敌方作战单元呈现以下威胁状态：杀伤链响应速度为 7min，杀伤链闭合概率为 65%，支援到达时间为 18min，协同打击系数为 0.6；目标种类为常规作战平台（DDG 驱逐舰），武器配置为常规导弹 / 炸弹（“鱼叉” 反舰导弹），干扰能力为基础电子干扰（DDG 驱逐舰 SLQ-32 (V) 系统），协作模式为有人 - 有人协同（DDG 与 CG 编队协同）；后援系统响应时间为 25min，作战续航时长为 12h。
    # """
    # print(get_threat_score(input_str))