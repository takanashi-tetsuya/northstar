@echo off
chcp 65001 > nul
echo =========================================
echo       Northstar XMPP Server 一键启动
echo =========================================

:: 必须从忽略提交的 .env 读取本地配置；不要在脚本或日志中打印连接串。
if exist ".env" (
    echo [INFO] 检测到 .env 文件，将使用其中的环境变量配置。
) else (
    echo [ERROR] 未检测到 .env。请复制 .env.example 为 .env 并填写本地配置。
    exit /b 1
)

echo [INFO] 正在编译并启动服务器...
cargo run --locked

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] 服务器运行意外终止或启动失败。
    echo 请检查上方错误日志。如果是连接被拒绝，请确认本地 PostgreSQL 服务是否已启动且用户名密码正确。
)

echo.
pause
