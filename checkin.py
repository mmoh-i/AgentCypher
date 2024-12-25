from langchain_cohere import ChatCohere
from langchain_core.messages import HumanMessage, SystemMessage
import os
from dotenv import load_dotenv

load_dotenv()

model = ChatCohere(model="command-r-plus", api_key= "2smrvRsEZIsipK901pcWX0JxH80ZH68V4OczMKyy") #os.getenv("COHERE_API_KEY"))
messages = [
    SystemMessage(content="You are a helpful assistant."),
    HumanMessage(content="Hello!")
]
response = model.invoke(messages)
print(response.content)