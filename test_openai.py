import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # đọc .env
api_key = os.getenv("OPENAI_API_KEY")

print(">>> DEBUG: API KEY nạp vào =", api_key[:20] + "...")  # in 20 ký tự đầu

client = OpenAI(api_key=api_key)

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello from Flask!"}]
    )
    print(">>> SUCCESS:", response.choices[0].message.content)
except Exception as e:
    print(">>> ERROR:", e)
