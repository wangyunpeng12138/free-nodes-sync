@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [x] 未找到 python，请先安装 Python 3.9+ 并加入 PATH
  pause
  exit /b 1
)

echo === 拉取上游 txt 订阅并转换为 Clash 配置 ===
python src\txt2clash.py %*
if errorlevel 1 (
  echo.
  echo [x] 转换失败，请检查网络（可先设置代理：set HTTPS_PROXY=http://127.0.0.1:7890）
  pause
  exit /b 1
)

echo.
echo [ok] 完成，输出目录：%~dp0output
endlocal
