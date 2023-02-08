@echo off&title=Python镜像源配置
echo 
echo.
echo 正在配置中……
echo.
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
echo 
echo.
echo 配置完成！
echo.
pip install -r requirements.txt
echo 
echo.&pause