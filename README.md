# mlviewer
An iOS, Android application memory view & edit PyQt6 application powered by Frida.<br>
It's a program running some useful frida scripts with ui to help mobile app analysis.

# Prerequisite
```
python > 3.8.0
Running frida-server on your device
```

# Usage
Two ways to run<br>
1.&nbsp;Python Virtual Environment (recommended)<br>
```
# Git clone
git clone https://github.com/hackcatml/mlviewer
cd mlviewer

# Run
.\mlviewer_wincon.bat (for Windows)
./mlviewer_macos.sh (for macOS)
```

2.&nbsp;Current Python Environment
```
# Git clone
git clone https://github.com/hackcatml/mlviewer
cd mlviewer

# Install requirements
pip install -r requirements.txt

# Install capstoen
pip install capstone
pip install --pre --no-binary capstone capstone (for m1, m2 macOS)

# Run
python main.py
```

# Update
```
git pull origin main
```

# Credits
[dump-ios-module](https://github.com/lich4)<br>
[dump-so](https://github.com/lasting-yang/frida_dump)<br>
[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)<br>
[https://armconverter.com](https://armconverter.com)<br>
[capstone](https://www.capstone-engine.org/)<br>
[frida-dexdump](https://github.com/hluwa/frida-dexdump)<br>
[bindiff](https://github.com/dadadel/bindiff)<br>
[cheat-engine](https://github.com/cheat-engine/cheat-engine)