@echo off
cd D:\llm-firewall
call venv\Scripts\activate
uvicorn proxy:app --host 0.0.0.0 --port 8001