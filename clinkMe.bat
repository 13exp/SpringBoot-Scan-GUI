@echo off&title=Python����Դ����
echo 
echo.
echo ���������С���
echo.
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
echo 
echo.
echo ������ɣ�
echo.
pip install -r requirements.txt
echo 
echo.&pause