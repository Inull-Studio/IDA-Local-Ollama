# Please install OpenAI SDK first: `pip3 install openai`

from openai import OpenAI
import os

API_KEY = os.getenv('DEEPSEEK_API_KEY')
client = OpenAI(api_key=API_KEY, base_url="https://api.deepseek.com/v1")

response = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "system", "content": "You are a helpful assistant"},
        {"role": "user", "content": "Hello"},
    ],
    stream=True
)

print(response.choices[0].message.content)