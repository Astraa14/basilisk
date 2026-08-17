import ast
with open(r'C:\Users\Administrator\Documents\Basilisk\basilisk\cache_control.py', 'r', encoding='utf-8') as f:
    content = f.read()
try:
    tree = ast.parse(content)
    print('OK - no syntax errors')
except SyntaxError as e:
    print(f'Syntax error at line {e.lineno}')
    lines = content.split('\n')
    print(f'Problem line ({e.lineno}): {repr(lines[e.lineno-1])}')
    # Show context
    start = max(0, e.lineno-4)
    end = min(len(lines), e.lineno+2)
    for i in range(start, end):
        marker = '^' * min(e.offset or 0, len(lines[i])) if i == e.lineno-1 else ''
        print(f'{i+1}: {lines[i]} {marker}')