import ast
with open(r'C:\Users\Administrator\Documents\Basilisk\basilisk\cache_control.py', 'r') as f:
    content = f.read()
# Try parsing each function separately
import re
functions = re.split(r'def |\nclass ', content)
for i, func in enumerate(functions[:10]):
    try:
        ast.parse(func)
        print(f"Function {i}: OK")
    except SyntaxError as e:
        print(f"Function {i}: Syntax error at line {e.lineno}")