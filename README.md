# mlviewer
An iOS, Android application memory view & edit PyQt6 application powered by Frida<br>
It's a program running some useful frida scripts with ui to help mobile app analysis

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

# Example
- Attach, move to an offset from the image base address, patch hex code<br>
![화면 기록 2023-06-21 오후 11 56 29](https://github.com/hackcatml/mlviewer/assets/75507443/7f3e3f7a-93c7-45c9-a7d5-f28fc026e43e)

- Hex to Arm convert (needs internet connection)<br>
Drag some hex bytes, mouse right button, click "Hex to Arm"<br>
![화면 기록 2023-06-22 오전 12 06 56](https://github.com/hackcatml/mlviewer/assets/75507443/330f2847-3f3e-4434-b4d1-1a2c1bb3d8be)

- Watch arguments, regs on address<br>
Select address, mouse right button, click "Set Watch Func" or "Set Watch Regs"<br>
You can monitor arguments with the read option during a function's onEnter or onLeave<br>
Select args, mouse right button, choose options(ex. select 'args0', check 'onLeave', 'readUtf8String' will log args0.readUtf8String() at onLeave)<br>
![화면 기록 2023-07-02 오후 10 22 58](https://github.com/hackcatml/mlviewer/assets/75507443/fb6d8a34-cc16-4334-a128-2970a0fb3317)

- Other examples<br>
so file dump, memory scan, etc<br>
https://hackcatml.tistory.com/174

# Credits
[dump-ios-module](https://github.com/lich4)<br>
[dump-so](https://github.com/lasting-yang/frida_dump)<br>
[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)<br>
[https://armconverter.com](https://armconverter.com)
[capstone](https://www.capstone-engine.org/)