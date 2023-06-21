# mlviewer
Memory View & Edit PyQt6 application powered by Frida<br>
It's a program running some useful frida scripts with ui


# Prerequisite
```
python > 3.8.0
Running frida-server on your device
```

# Usage
Run
```
git clone https://github.com/hackcatml/mlviewer

cd mlviewer

pip install -r requirements.txt

python main.py
```

# Example
- Attach, move to an offset from the image base address, patch hex code<br>
![화면 기록 2023-06-21 오후 11 56 29](https://github.com/hackcatml/mlviewer/assets/75507443/7f3e3f7a-93c7-45c9-a7d5-f28fc026e43e)

- Hex to Arm convert (needs internet connection)<br>
Drag some hex bytes, mouse right button, click "Hex to Arm"<br>
![화면 기록 2023-06-22 오전 12 06 56](https://github.com/hackcatml/mlviewer/assets/75507443/330f2847-3f3e-4434-b4d1-1a2c1bb3d8be)

- Other examples<br>
so file dump, memory scan, etc<br>
https://hackcatml.tistory.com/174


# Credits
[dump-ios-module](https://github.com/lich4)<br>
[dump-so](https://github.com/lasting-yang/frida_dump)<br>
[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)<br>
[https://armconverter.com](https://armconverter.com)
