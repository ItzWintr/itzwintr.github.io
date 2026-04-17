import re

with open('f:/WEEB DEVELOPING/portfolio v2/writeups/SILENTIUMHTB/index.html', 'r', encoding='utf-8') as f:
    template = f.read()

with open('f:/WEEB DEVELOPING/portfolio v2/writeups/PYRATTHM/Pyrat TryHackMe.md', 'r', encoding='utf-8') as f:
    markdown = f.read()

template = re.sub(r'<title>.*?</title>', '<title>Pyrat - TryHackMe Machine</title>', template)

parts = template.split('<textarea id="embedded-markdown" style="display:none;">')
new_content = parts[0] + '<textarea id="embedded-markdown" style="display:none;">\n' + markdown.strip() + '\n</textarea>\n</body>\n</html>\n'

with open('f:/WEEB DEVELOPING/portfolio v2/writeups/PYRATTHM/index.html', 'w', encoding='utf-8') as f:
    f.write(new_content)
print("Done")
