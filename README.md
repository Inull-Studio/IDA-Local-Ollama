### 测试环境

-   [x] Windows 10/11-IDA 9.0-IDAPython 3.8.10
-   [x] MacOS-IDA 9.0-IDAPython 3.9.6

![image-20241226102127346](./README.assets/image-20241226102127346.png)

![image-20241226102139356](./README.assets/image-20241226102139356.png)

### Install

#### 本地部署ollma并下载好模型

并在代码以下部分替换成自己想用的模型

```PYTHON
model_name_1 = 'qwen2.5:3b-instruct-q8_0'  # 第一个智能体使用的模型
model_name_2 = 'qwen2.5:3b-instruct-q8_0'  # 第二个智能体使用的模型
```

#### 先检查IDA

```python
import sys
print(sys.version)
```

![image-20241226101902179](./README.assets/image-20241226101902179.png)

#### 在idaapi.py脚本开头替换对应python版本的路径

```python
import sys
sys.path.append('/Users/lovensar/.pyenv/versions/3.9.6/lib/python3.9/site-packages')
import ollama #之前已经用pip安装好了ollama
```

可能会与到报错：

报错ModuleNotFoundError: No module named 'pydantic_core._pydantic_core’。

我看路径是3.11.8，然后输入`pyenv global 3.9.6`

#### 替换好之后，重启IDA

![image-20241226102056297](./README.assets/image-20241226102056297.png)

然后我们可以开始了。

做了两天时间，目前只做了全局变量和函数名称。