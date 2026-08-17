with open(r'C:\Users\Administrator\Documents\Basilisk\basilisk\cache_control.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Print lines 190-215 with indentation tracking
for i in range(189, 215):
    line = lines[i]
    indent = len(line) - len(line.lstrip())
    print(f'{i+1}: {indent:3d} | {line.rstrip()}')