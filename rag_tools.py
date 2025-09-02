# coding=utf-8
# @Time : 2025/8/18 17:01
# @Author : RoseLee
# @File : rag_tools
# @Project : threat-assessment
# @Description :对文本进行向量化，进行威胁评估分数查询
import pandas as pd
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain.vectorstores import FAISS
from langchain.tools.retriever import create_retriever_tool
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.embeddings import DashScopeEmbeddings
from langchain.chat_models import init_chat_model
import os
from prompt.prompt_loader import PromptLoader
from base import LLMClient
import configs
from configs import DeepSeek_API_KEY,Dashscope_Api_Key
from util import response_extractor
import re
os.environ["DEEPSEEK_API_KEY"] = DeepSeek_API_KEY

BATCH_SIZE = 10
embeddings = DashScopeEmbeddings(
    model="text-embedding-v4", dashscope_api_key=Dashscope_Api_Key
)
def get_chunks(text:str):
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = text_splitter.split_text(text)
    return chunks


def vector_store(text_chunks:list):
    """将文本块分批次存储到FAISS向量数据库"""
    if not text_chunks:
        return False

    # try:
    try:
        db = FAISS.load_local("faiss_db", embeddings)
    except:
        first_batch = text_chunks[:BATCH_SIZE]
        db = FAISS.from_texts(first_batch, embedding=embeddings)
        remaining_chunks = text_chunks[BATCH_SIZE:]
    else:
        remaining_chunks = text_chunks

    # 分批次添加剩余的文本块
    for i in range(0, len(remaining_chunks), BATCH_SIZE):
        batch = remaining_chunks[i:i + BATCH_SIZE]
        db.add_texts(batch)

    # 保存更新后的数据库
    db.save_local("faiss_db")
    return True
    # except Exception as e:
    #     print(f"存储向量时发生错误: {str(e)}")
    #     return False

def get_conversational_chain(tools, ques):
    """
    使用agent执行任务
    :param tools:
    :param ques:
    :return:
    """
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
    """
    配置检索工具
    :param question:具体问题
    :return:
    """
    new_db = FAISS.load_local("faiss_db", embeddings, allow_dangerous_deserialization=True)
    retriever = new_db.as_retriever()
    retrieval_chain = create_retriever_tool(retriever, "information_extractor",
                                            "This tool is to give answer to queries from the '历史作战案例库'")
    return get_conversational_chain(retrieval_chain, question)


def query_for_similarity(environment_description):
    """
    根据相似度查找对应案例
    :param environment_description:
    :return:
    """
    db = FAISS.load_local("faiss_db", embeddings, allow_dangerous_deserialization=True)
    retriever = db.as_retriever(search_kwargs={"k": 1})  # 只返回最相似的结果
    similar_docs = retriever.get_relevant_documents(environment_description)

    if not similar_docs:
        return "未找到相似案例"

    # 从最相似的案例中提取威胁分数
    most_similar_case = similar_docs[0].page_content
    # 简单规则提取（若分数格式固定，如“威胁分数为：XX”）
    score_match = re.search(r"威胁分数为：(\d+)", most_similar_case)
    if score_match:
        return f"最相似案例的威胁分数为：{score_match.group(1)}"
    else:
        return "未在相似案例中找到威胁分数"




def retrieval_data_storage(file_path:str, sheet_name:str):
    """
    从Excel文件读取数据并存储到向量数据库

    :param file_path: Excel文件路径
    :return: 存储是否成功
    """
    df = pd.read_excel(file_path, sheet_name=sheet_name, header=None)
    all_chunks = []
    for index, row in df.iterrows():
        text = str(row[0])
        if text.strip():
            chunks = get_chunks(text)
            all_chunks.extend(chunks)
    return vector_store(all_chunks)

def classify_level(description:str) -> str:
    """
    对输入描述进行分级
    :param description:输入描述
    :return: 分级结果，字符串
    """
    llm = LLMClient(configs.DEEPSEEK_V3_CONFIG)
    return response_extractor(
        llm.infer(
            system_prompt='你是一个分级专家',
            user_prompt=PromptLoader.get_prompt(
                prompt_name='rag/environment_classification.prompt',
                environment_description=description
            )
        )
    ).get("result")

def get_threat_score(environment_desp):
    """
    获取威胁分数
    :param environment_desp:
    :return:
    """
    level_result = classify_level(
            description=environment_desp
        )
    environment = query_for_similarity(level_result)
    response = query(PromptLoader.get_prompt(prompt_name='rag/retrieval_case_lib.prompt',environment=environment)).get('output')
    score_match = re.search(r"威胁分数为：(\d+)", response)

    return score_match.group(1)

if __name__ == '__main__':
    # 存储指定的库
    # retrieval_data_storage(file_path='./resource/level.xlsx', sheet_name='历史作战案例库')


    PromptLoader.from_paths(['./prompt'])
    # 模拟生成的环境情况
    input_str = """
            在某近岸海域，海水温度为 25 摄氏度，风速 5m/s，过去 48 小时累计降水量 30mm，海洋流速 0.3m/s，该区域平均水深 60 米，电磁干扰中高频长、中、短波（0.1-30MHz）强度 8V/m，超短波（30-300MHz）强度 3V/m。
            """
    print(get_threat_score(input_str))


